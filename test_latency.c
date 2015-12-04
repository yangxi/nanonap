#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <sched.h>

#define debug_print(...) fprintf (stderr, __VA_ARGS__)

typedef struct {
  int index;
  int fd;
  struct perf_event_attr perf_attr;
  struct perf_event_mmap_page *buf;
  char * name;
}hw_event_t;

static void bind_processor(int cpu)
{
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static char *copy_name(char *name)
{
  char *dst = (char *)malloc(strlen(name) + 1);
  strncpy(dst, name, strlen(name) + 1);
  return dst;
}

static void create_hw_event(char *name, hw_event_t *e)
{
  struct perf_event_attr *pe = &(e->perf_attr);
  int ret = pfm_get_perf_event_encoding(name, PFM_PLM3, pe, NULL, NULL);
  if (ret != PFM_SUCCESS) {
    errx(1, "error creating event '%s': %s\n", name, pfm_strerror(ret));
  }
  pe->sample_type = PERF_SAMPLE_READ;
  e->fd = perf_event_open(pe, 0, -1, -1, 0);
  if (e->fd == -1) {
    err(1, "error in perf_event_open for event %s", name);
  }
  //mmap the fd to get the raw index
  e->buf = (struct perf_event_mmap_page *)mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ, MAP_SHARED, e->fd, 0);
  if (e->buf == MAP_FAILED) {
    err(1,"mmap on perf fd %d %s", e->fd, name);
  }

  e->name = copy_name(name);

  e->index = e->buf->index - 1;
  debug_print("Creat hardware event name:%s, fd:%d, index:%x\n",
	      name,
	      e->fd,
	      e->index);
}

static hw_event_t * shim_create_hw_events(int nr_hw_events, char **hw_event_names)
{
  //relase old perf events
  int i;

  hw_event_t * hw_events = (hw_event_t *) calloc(nr_hw_events, sizeof(hw_event_t));
  if (hw_events == NULL)
    return NULL;

  for (i=0; i<nr_hw_events; i++){
    create_hw_event(hw_event_names[i], hw_events + i);
  }
  for (i=0;i <nr_hw_events; i++){
    hw_event_t *e = hw_events + i;
    debug_print("updateindex event %s, fd %d, index %x\n", e->name, e->fd, e->buf->index - 1);
    e->index = e->buf->index - 1;
  }
  return hw_events;
}


unsigned long *kernel_tsc(unsigned long  phyaddr)
{
  unsigned long mmap_offset = phyaddr & 0xfffffffffffff000;
  int mmap_size = 0x1000;
  int tsc_offset = phyaddr - mmap_offset;
  int mmap_fd;

  if ((mmap_fd = open("/dev/mem", O_RDWR)) < 0) {
    fprintf(stderr,"Can't open /dev/mem");
    return NULL;
  }
  char *mmap_addr = mmap(0, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, mmap_fd, mmap_offset);
  if (mmap_addr == MAP_FAILED) {
    fprintf(stderr,"Can't mmap /dev/mem\n");
    return NULL;
  }
  printf("mmap phy %lx at vir %p, so %lxxsap is %p\n", mmap_offset, mmap_addr, phyaddr, mmap_addr + tsc_offset);
  return (unsigned long *)(mmap_addr + tsc_offset);
}

static unsigned long __inline__ rdtsc(void)
{
  unsigned int tickl, tickh;
  __asm__ __volatile__("rdtscp":"=a"(tickl),"=d"(tickh)::"%ecx");
  return ((uint64_t)tickh << 32)|tickl;
}

volatile int flag = -1;
unsigned long cycles[2];
void * worker_start(void *p)
{
  bind_processor(9);
  debug_print("Worker is ready\n");
  flag = 0;

  int fd = open("/dev/c1latency", O_RDONLY| O_CLOEXEC);
  if (fd < 0){
    fprintf(stderr, "Can't open /dev/c1latnecy\n");
    exit(0);
  }

  while(1) {
    if (flag == 1){
      debug_print("start ioctl\n");
      cycles[0] = rdtsc();
      ioctl(fd, 0, NULL);
      cycles[1] = rdtsc();
      flag = 2;
      debug_print("end ioctl\n");
    }
  }
}

#define LOG_SIZE 1024*1024
//usage: test_latency phy_addr event0 event1 ...
static char *usage = "test_latency phy_addr event0 event1 ... eventn";
int main(int ac, char **av)
{
  int i;
  if (ac < 2){
    printf("%s\n", usage);
    exit(0);
  }
  unsigned long counters[2];
  unsigned long * logs;

  bind_processor(1);
  int ret = pfm_initialize();
  if (ret != PFM_SUCCESS) {
    err(1,"pfm_initialize() is failed!");
    exit(-1);
  }
  debug_print("av[1] is %s\n", av[1]);
  unsigned long kernel_buf_addr = strtoul(av[1], NULL, 16);
  debug_print("Kernel address %lx\n", kernel_buf_addr);
  hw_event_t *events = shim_create_hw_events(ac-2, av+2);
  unsigned long *buf = kernel_tsc(kernel_buf_addr);
  pthread_t task;
  pthread_create(&task, NULL, worker_start, NULL);
  logs = calloc(LOG_SIZE, sizeof(unsigned long));
  memset(logs, 0, LOG_SIZE * sizeof(unsigned long));
  while (flag == -1)
    ;
  //start to test
  printf("set flag to 1\n");
  counters[0] = rdtsc();
  flag = 1;
  //let's keep 1MB logs, see whether we can find interesting IPC numbers
  //tsp_start, event0, event1, tsp_end
  int log_index = 0;
  while(log_index + 4 < LOG_SIZE){
    unsigned long *p = logs + log_index;
    p[0] = rdtsc();
    p[1] = __builtin_ia32_rdpmc(events[0].index);
    p[2] = __builtin_ia32_rdpmc(events[1].index);
    p[3] = rdtsc();
    log_index += 4;
  }
  printf("touch buf[0]\n");
  buf[0] = 0xdead;
  while (flag != 2)
    ;
  counters[1] = rdtsc();
  printf("%lx->%lu->%lu->%lu->%lu->%lu\n",
	 counters[0], cycles[0]-counters[0], buf[1]-counters[0], buf[2]-counters[0], cycles[1]-counters[0], counters[1]-counters[0]);
  printf("%lu->%lu->%lu->%lu->%lu->%lu\n",
	 counters[0], cycles[0], buf[1], buf[2], cycles[1], counters[1]);
  for (log_index=4; log_index < LOG_SIZE; log_index += 4){
    unsigned long *prev = logs + log_index - 4;
    unsigned long *curr = logs + log_index;
    printf("%lu,%lu,%lu,%lu\n", curr[0],curr[1]-prev[1],curr[2]-prev[2],curr[3]-prev[3]);
  }
}
