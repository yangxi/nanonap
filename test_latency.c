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
#include <syscall.h>
#include <linux/futex.h>


#ifdef DEBUG
#define PRINT_RAW_DATA
#define debug_print(...) fprintf (stderr, __VA_ARGS__)
#else
#define debug_print(...)
#endif

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

//return the array the kernel operats on
//kernel sleeps on ret[0], put start tsc of "mwait" in ret[1], end of "mwait" in ret[2]
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
  debug_print("mmap phy %lx at vir %p, so %lxxsap is %p\n", mmap_offset, mmap_addr, phyaddr, mmap_addr + tsc_offset);
  return (unsigned long *)(mmap_addr + tsc_offset);
}

static unsigned long __inline__ rdtsc(void)
{
  unsigned int tickl, tickh;
  __asm__ __volatile__("rdtscp":"=a"(tickl),"=d"(tickh)::"%ecx");
  return ((uint64_t)tickh << 32)|tickl;
}

#define FLAG_INIT  (-1)
#define FLAG_WORKER_WAKEUP (0)
#define FLAG_WORKER_SLEEP (1)
#define FLAG_WORKER_ACTION (2)

volatile int flag = -1;

unsigned long worker_tsc[2];

#define NANONAP (1)
#define SLEEP_FUTEX (2)

int sleep_style = NANONAP;

int futex_flag = 0;
int futex_wait(){
  syscall(SYS_futex,&futex_flag,0, NULL, NULL, 0);
  futex_flag = 0;
}
int futex_wake(){
  return syscall(SYS_futex, &futex_flag, FUTEX_WAKE, 1, NULL, NULL, 0);
}

void * worker_start(void *p)
{
  bind_processor(9);
  debug_print("Worker is ready\n");
  flag = FLAG_WORKER_WAKEUP;

  int fd = open("/dev/c1latency", O_RDONLY| O_CLOEXEC);
  if (fd < 0){
    fprintf(stderr, "Can't open /dev/c1latnecy\n");
    exit(0);
  }

  while(1) {
    if (flag == FLAG_WORKER_ACTION){
      //      debug_print("Worker start ioctl\n");
      flag = FLAG_WORKER_SLEEP;
      worker_tsc[0] = rdtsc();

      if (sleep_style == NANONAP)
	ioctl(fd, 0, NULL);
      else
	futex_wait();

      worker_tsc[1] = rdtsc();
      flag = FLAG_WORKER_WAKEUP;
      debug_print("Worker end ioctl\n");
    }
  }
}

int dummy_payload(unsigned long input)
{
  int i;
  for (i=0;i<32;i=i+1)
    input *=2;
}

unsigned long  report_stat(int i, unsigned long *m_tsc, unsigned long *w_tsc, unsigned long *k_tsc, unsigned long *logs);
#define LOG_SIZE 1024
//usage: test_latency phy_addr event0 event1 ...
static char *usage = "test_latency phy_addr flag event0 event1 event2 event3\n sudo ./test_latency 0x40f02f000 1 UOPS_RETIRED:u:k UOPS_RETIRED:u:k:t INSTRUCTION_RETIRED:u:k INSTRUCTION_RETIRED:u:k:t";
int main(int ac, char **av)
{
  int i;
  if (ac < 7){
    printf("%s\n", usage);
    exit(0);
  }
  unsigned long m_tsc[3];
  unsigned long * logs, *logs_up;

  bind_processor(1);
  int ret = pfm_initialize();
  if (ret != PFM_SUCCESS) {
    err(1,"pfm_initialize() is failed!");
    exit(-1);
  }
  sleep_style = atoi(av[2]);
  debug_print("av[1] is %s\n", av[1]);
  unsigned long kernel_buf_addr = strtoul(av[1], NULL, 16);
  debug_print("Kernel address %lx\n", kernel_buf_addr);
  hw_event_t *events = shim_create_hw_events(ac-3, av+3);
  unsigned long *k_tsc = kernel_tsc(kernel_buf_addr);
  pthread_t task;
  pthread_create(&task, NULL, worker_start, NULL);
  logs = calloc(LOG_SIZE, sizeof(unsigned long));
  logs_up = calloc(LOG_SIZE, sizeof(unsigned long));
  memset(logs, 0, LOG_SIZE * sizeof(unsigned long));
  memset(logs_up, 0, LOG_SIZE * sizeof(unsigned long));
  //wait for worker ready
  while (flag == FLAG_INIT)
    ;
  //start to test
  //  printf("set flag to 1\n");
  for (i=0; i<100; i=i+1) {
    m_tsc[0] = rdtsc();
    flag = FLAG_WORKER_ACTION;
    //    while (flag != FLAG_WORKER_SLEEP)
    //      ;
    //let's keep 1MB logs, see whether we can find interesting IPC numbers
    //tsp_start, event0, event1, tsp_end
    int log_index = 0;
    while(log_index + 4 <= LOG_SIZE){
      unsigned long *p = logs + log_index;
      p[0] = rdtsc();
      p[1] = __builtin_ia32_rdpmc(events[0].index);
      p[2] = __builtin_ia32_rdpmc(events[1].index);
      p[3] = rdtsc();
      log_index += 4;
      //      dummy_payload(p[0]);
    }

    if (flag != FLAG_WORKER_SLEEP){
      fprintf(stderr, "Error: flag should be %d, but is %d\n", FLAG_WORKER_SLEEP, flag);
      exit(1);
    }
    //let's wake up the worker
    m_tsc[1] = rdtsc();
    if (sleep_style == NANONAP)
      k_tsc[0] = 0xdead;
    else
      futex_wake();


    log_index = 0;
    while (flag != FLAG_WORKER_WAKEUP){
      unsigned long *p = logs_up + log_index;
      p[0] = rdtsc();
      p[1] = __builtin_ia32_rdpmc(events[2].index);
      p[2] = __builtin_ia32_rdpmc(events[3].index);
      p[3] = rdtsc();
      log_index += 4;
      if (log_index == LOG_SIZE){
	fprintf(stderr, "Error: log_index is rounded\n");
	exit(1);
      }
    }
    m_tsc[2] = rdtsc();
    unsigned long sleep_latency = report_stat(i, m_tsc, worker_tsc, k_tsc, logs);
    unsigned long wakeup_latency = m_tsc[2] - logs_up[0];
    printf("%d:%ld %ld\n", i, sleep_latency, wakeup_latency);
    sleep(1);
    debug_print("Collect %d samples %ld cycles before worker woken up\n", log_index, m_tsc[2] - logs_up[0]);
#ifdef PRINT_RAW_DATA
    int t;
    for (t=4; t<log_index; t=t+4){
      unsigned long *prev = logs_up + t - 4;
      unsigned long *curr = logs_up + t;
      printf("UP:%lu,%lu,%lu,%lu\n", curr[0],curr[1]-prev[1],curr[2]-prev[2],curr[3]-prev[3]);
    }
#endif

  }
}


//#define PRINT_RAW_DATA
//i->iteration, m_tsc->main_tsc, w_tsc->worker_tsc, k_tsc->kernel_tsc
//m_tsc[0] ---- w_tsc[0] ---ioctl--k_tsc[1]---monitor/mwait----m_tsc[1]---wakeup---k_tsc[2]---ret from ioctl--w_tsc[1]--setflag---m_tsc[2]
unsigned long report_stat(int iter, unsigned long *m_tsc, unsigned long *w_tsc, unsigned long *k_tsc, unsigned long *logs)
{
  int i,j,k;

  debug_print("--------------------%d-------------\n", iter);
  debug_print("#m_tsc[0] ---- w_tsc[0] ---ioctl--k_tsc[1]---monitor/mwait----m_tsc[1]---wakeup---k_tsc[2]---ret from ioctl--w_tsc[1]--setflag---m_tsc[2]\n");
  debug_print("stages_diff:%lx->%lu->%lu->%lu->%lu->%lu->%lu\n",
	 m_tsc[0], w_tsc[0]-m_tsc[0], k_tsc[1]-w_tsc[0], m_tsc[1] - k_tsc[1],k_tsc[2] - m_tsc[1], w_tsc[1] - k_tsc[2], m_tsc[2] - w_tsc[1]);
  debug_print("#stages_raw:%lu->%lu->%lu->%lu->%lu->%lu->%lu\n",
	 m_tsc[0], w_tsc[0], k_tsc[1], m_tsc[1], k_tsc[2], w_tsc[1], m_tsc[2]);
  //let's search the latency of releasing resources
  unsigned long start_mwait = k_tsc[1];
  int start_index = 0;
  int end_index = 0;
  start_index = 0;
  for(j=0;j + 4 <=LOG_SIZE;j=j+4){
	int heat = 0;
	int nr_step = 0;
	for(k=j;k + 8 < LOG_SIZE;k=k+4){
	  nr_step += 1;
	  unsigned long *cur = logs + k;
	  unsigned long *next = cur +4;
	  if (next[1] - cur[1] == next[2] - cur[2])
	    heat += 1;
	  if (nr_step == 20 && heat == 20)
	    end_index = j;
	  if (nr_step == 20)
	    break;
	}
	if (end_index != 0)
	  break;
  }

  debug_print("#start_index:%d, end_index:%d\n", start_index, end_index);
  unsigned long mwait_latency = logs[end_index] - m_tsc[0];
  debug_print("#start_tsc:%lu, end_tsc:%lu\n", *(logs + start_index), *(logs+end_index));
  debug_print("sleep:%lu\n", logs[end_index] - m_tsc[0]);

  //#define PRINT_RAW_DATA
#ifdef PRINT_RAW_DATA
  int log_index;
  debug_print("stages:%lu->%lu->%lu->%lu->%lu->%lu->%lu\n",
	 m_tsc[0], w_tsc[0], k_tsc[1], m_tsc[1], k_tsc[2], w_tsc[1], m_tsc[2]);
  for (log_index=4; log_index < LOG_SIZE; log_index += 4){
    unsigned long *prev = logs + log_index - 4;
    unsigned long *curr = logs + log_index;
    debug_printf("%lu,%lu,%lu,%lu\n", curr[0],curr[1]-prev[1],curr[2]-prev[2],curr[3]-prev[3]);
  }
#endif
  return   mwait_latency;
}
