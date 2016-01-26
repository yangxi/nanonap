#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <perfmon/pfmlib_perf_event.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <getopt.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>

///aha disk idle 141477068
///aha disk idle 397833656

#define debug_print(...) fprintf (stderr, __VA_ARGS__)

static unsigned long __inline__ rdtsc(void)
{
  unsigned int tickl, tickh;
  __asm__ __volatile__("rdtscp":"=a"(tickl),"=d"(tickh)::"%ecx");
  return ((uint64_t)tickh << 32)|tickl;
}

int grab_os_signals(int cpu, unsigned long ** ppid, int ** syscall)
{
  char buf[1024];
  unsigned long signal_phy_addr[32];
  int fd;
  int i;

  if ((fd = open("/sys/module/simple_pt/parameters/shim_signal", O_RDONLY)) < 0){
    fprintf(stderr, "Can't open /sys/module/simple_pt/parameters/shim_signal\n");
    return 1;
  }
  int nr_read = read (fd, buf, 1024);
  debug_print("read %d bytes %s from shim_sginal\n", nr_read, buf);
  signal_phy_addr[0] = atol(buf);
  char *cur = buf;
  for (i=1; i<32; i=i+1){
    while (*(cur++) != ',')
      ;
    signal_phy_addr[i] = atol(cur);
  }
  close(fd);

  unsigned long mmap_offset = signal_phy_addr[cpu * 2] & 0xffffffffffff0000;
  int mmap_size = 0x10000;
  int syscall_offset = signal_phy_addr[cpu * 2] - mmap_offset;
  int task_offset = signal_phy_addr[cpu * 2 + 1] - mmap_offset;
  int mmap_fd;

  if ((mmap_fd = open("/dev/mem", O_RDONLY)) < 0) {
    fprintf(stderr,"Can't open /dev/mem");
    return 1;
  }
  char *mmap_addr = mmap(0, mmap_size, PROT_READ, MAP_SHARED, mmap_fd, mmap_offset);
  if (mmap_addr == MAP_FAILED) {
    fprintf(stderr,"Can't mmap /dev/mem");
    return 1;
  }
  *ppid = (unsigned long *)(mmap_addr + task_offset);
  *syscall = (int *)(mmap_addr + syscall_offset);
  debug_print("mmap /dev/mem on fd:%d, offset 0x%lx, at addr %p, ppid %p, syscall %p\n",
	   mmap_fd, mmap_offset, mmap_addr, *ppid, *syscall);
  return 0;
}

static void bind_processor(int cpu)
{
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

unsigned long * grab_lucene_signals()
{
  int fd = open("/home/yangxi/benchmark/lucene/util/lucene_signal", O_RDWR);
  if (fd == -1){
    err(1, "Can't open ./lucene_signal\n");
    exit(1);
  }
  unsigned long * lucene_signal_buf = (unsigned long *)mmap(0, 0x1024, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if (lucene_signal_buf == MAP_FAILED){
    err(1, "Can't mmap ./lucene_signal\n");
    exit(1);
  }
  return lucene_signal_buf;
}

volatile unsigned long *ppid;
volatile int *nr_syscall;
volatile unsigned long *lucene;

struct idle_log{
  unsigned long ppid;
  unsigned long lucene;
  unsigned long timestamp;
  unsigned long busy;
};

void probe_signals(struct idle_log *buf)
{
  buf->ppid = *ppid;
  buf->lucene = *lucene;
  buf->timestamp = rdtsc();
  buf->busy = buf->ppid > 0? 1 : 0;
}



#define MAX_LOGS (10000)

int
main(int argc, char **argv)
{
  printf("Bind to CPU 2\n");
  bind_processor(2);


  grab_os_signals(0, &ppid, &nr_syscall);
  lucene = grab_lucene_signals();



  struct idle_log states[2];
  struct idle_log *logs = (struct idle_log *)malloc(MAX_LOGS * sizeof (struct idle_log));
  memset(logs, 0, MAX_LOGS * sizeof (struct idle_log));
  int last = 0;
  int now = 1;

  probe_signals(states + last);
  int nr_periods = 0;
  int start_record = 0;
  while(1){
    probe_signals(states + now);
    if (states[now].busy == states[last].busy)
      continue;

    //now we switch the flag
    //#tid pid task states
    long lucene_tag = (long)(states[last].lucene);
    int lu_task = (int)(states[last].lucene & 0xffffffff);
    int lu_stage = (int)(states[last].lucene >> 32);

    if (lucene_tag < 0){
      start_record = 1;
    }

    if (lu_task == 5704 && lu_stage == 2 && start_record){
      start_record = 0;
      break;
    }

    if (start_record){
      if (nr_periods < MAX_LOGS){
	logs[nr_periods] = states[last];
	logs[nr_periods].timestamp = states[now].timestamp - states[last].timestamp;;
      }
      nr_periods += 1;
#ifdef _DEBUG_
      struct idle_log *l = logs + nr_periods;
      int lu_task = (int)(l->lucene & 0xffffffff);
      int lu_stage = (int)(l->lucene >> 32);
      int tid = (int)(l->ppid & 0xffffffff);
      int pid = (int)(l->ppid >> 32);
      long  cycles = l->timestamp;
      printf("%d,%d,%d,%d,%d,%ld\n", (int)(l->busy), tid, pid, lu_task, lu_stage, cycles);
#endif
    }

    last ^= 1;
    now ^= 1;
  }

  int i;
  printf("#busy,tid,pid,lu_task,lu_stage,timestamp\n");
  for (i=0; i< nr_periods; i=i+1){
      struct idle_log * l = logs + i;
    int lu_task = (int)(l->lucene & 0xffffffff);
    int lu_stage = (int)(l->lucene >> 32);
    int tid = (int)(l->ppid & 0xffffffff);
    int pid = (int)(l->ppid >> 32);
    long  cycles = l->timestamp;
    printf("%d,%d,%d,%d,%d,%ld\n", (int)(l->busy), tid, pid, lu_task, lu_stage, cycles);
  }
}
