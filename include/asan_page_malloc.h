#ifndef ASAN_PAGE_MALLOC_H
#define ASAN_PAGE_MALLOC_H

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>

#define __ASAN_MAX_PAGES 1024
#define __ASAN_MAX_FRAMES 64
#define __ASAN_PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define __ASAN_HASH_SIZE 65536

#define PUTS_STDERR(s) write(STDERR_FILENO, (s "\n"), sizeof(s "\n") - 1)
#define HASH_ADDR(addr) ((unsigned long) (addr) / __ASAN_PAGE_SIZE) % __ASAN_HASH_SIZE

typedef struct __asan_metadatum {
  void *allocated_page;
  void *frames_alloc[__ASAN_MAX_FRAMES];
  void *frames_free[__ASAN_MAX_FRAMES];
  int frame_count_alloc;
  int frame_count_free;
  struct __asan_metadatum *next;
} __asan_metadatum_t;
__asan_metadatum_t __asan_metadata[__ASAN_MAX_PAGES];

__asan_metadatum_t *__asan_rev[__ASAN_HASH_SIZE];

int __asan_allocated_index;

void handle_sigsegv(int sig, siginfo_t *info, void *ucontext) {
  for (int i = 0; i < __asan_allocated_index; i++) {
    __asan_metadatum_t metadatum = __asan_metadata[i];
    if (metadatum.allocated_page <= info->si_addr &&
        info->si_addr < metadatum.allocated_page + __ASAN_PAGE_SIZE * 3) {
      PUTS_STDERR("[chibicc-ASan]");
      
      if (info->si_addr < metadatum.allocated_page + __ASAN_PAGE_SIZE) {
        PUTS_STDERR("buffer-underflow");
      } else if (info->si_addr < metadatum.allocated_page + __ASAN_PAGE_SIZE * 2) {
        PUTS_STDERR("use-after-free");
      } else {
        PUTS_STDERR("buffer-overflow");
      }

      PUTS_STDERR("allocated at:");
      backtrace_symbols_fd(metadatum.frames_alloc, metadatum.frame_count_alloc, STDERR_FILENO);

      if (metadatum.frame_count_free > 0) {
        PUTS_STDERR("freed at:");
        backtrace_symbols_fd(metadatum.frames_free, metadatum.frame_count_free, STDERR_FILENO);
      }
      _exit(sig + 128);
    }
  }

  PUTS_STDERR("Segmentation fault (chibicc)");
  _exit(sig + 128);
}

void asan_init() {
  struct sigaction act = { 0 };
  sigemptyset(&act.sa_mask);
  act.sa_handler = handle_sigsegv;
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &act, NULL);

  __asan_allocated_index = 0;
}

void *asan_page_malloc() {
  void *pages = mmap(NULL, __ASAN_PAGE_SIZE * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) {
    perror("mmap");
  }
  mprotect(pages + __ASAN_PAGE_SIZE, __ASAN_PAGE_SIZE, PROT_READ | PROT_WRITE);
  __asan_metadata[__asan_allocated_index].allocated_page = pages;
  int frame_count = backtrace(__asan_metadata[__asan_allocated_index].frames_alloc, __ASAN_MAX_FRAMES);
  __asan_metadata[__asan_allocated_index].frame_count_alloc = frame_count;

  __asan_metadatum_t *next = __asan_rev[HASH_ADDR(pages)];
  
  __asan_rev[HASH_ADDR(pages)] = &__asan_metadata[__asan_allocated_index];
  __asan_rev[HASH_ADDR(pages)]->next = next;
    
  __asan_allocated_index++;
  void *ret = pages + __ASAN_PAGE_SIZE;
  return ret;
}

void asan_page_free(void *ptr) {
  for (__asan_metadatum_t *p = __asan_rev[HASH_ADDR(ptr - __ASAN_PAGE_SIZE)]; ; p = p->next) {
    printf("%p\n", p);
    if (p == NULL) {
      abort();
    } else {
      if (p->allocated_page == ptr - __ASAN_PAGE_SIZE) {
        int frame_count = backtrace(p->frames_free, __ASAN_MAX_FRAMES);
        p->frame_count_free = frame_count;
        break;
      }
    }
  }
  if (mprotect(ptr, __ASAN_PAGE_SIZE, PROT_NONE) == -1) {
    perror("mprotect");
  }
}

#endif