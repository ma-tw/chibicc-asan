#ifndef ASAN_PAGE_MALLOC_H
#define ASAN_PAGE_MALLOC_H

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>

#define __ASAN_MAX_PAGES 1024

void *__asan_allocated_pages[__ASAN_MAX_PAGES];
int __asan_allocated_index;

void handle_sigsegv(int sig, siginfo_t *info, void *ucontext) {
  for (int i = 0; i < __asan_allocated_index; i++) {
    if (__asan_allocated_pages[i] <= info->si_addr &&
        info->si_addr < __asan_allocated_pages[i] + 4096) {
      char msg[] = "chibicc-ASan\n";
      write(STDERR_FILENO, msg, sizeof(msg) - 1);
      void *frames[64];
      int frame_count = backtrace(frames, 64);
      backtrace_symbols_fd(frames, frame_count, STDERR_FILENO);
      _exit(sig + 128);
    }
  }

  char msg[] = "Segmentation fault (chibicc)\n";
  write(STDERR_FILENO, msg, sizeof(msg) - 1);
  _exit(sig + 128);
}

void asan_init() {
  struct sigaction act = { 0 };
  sigemptyset(&act.sa_mask);
  act.sa_handler = handle_sigsegv;
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &act, NULL);

  for (int i = 0; i < __ASAN_MAX_PAGES; i++)
    __asan_allocated_pages[i] = NULL;

  __asan_allocated_index = 0;
}

void *asan_page_malloc() {
  void *ret = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ret == MAP_FAILED) {
    perror("mmap");
  }
  __asan_allocated_pages[__asan_allocated_index++] = ret;
  return ret;
}

void asan_page_free(void *p) {
  if (mprotect(p, 4096, PROT_NONE) == -1) {
    perror("mprotect");
  }
}

#endif