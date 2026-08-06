#ifndef ASAN_PAGE_MALLOC_H
#define ASAN_PAGE_MALLOC_H

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>
#include <stdbool.h>

#define __ASAN_MAX_PAGES 1024
#define __ASAN_MAX_FRAMES 64
#define __ASAN_PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define __ASAN_HASH_SIZE 65536

#define PUTS_STDERR(s) write(STDERR_FILENO, (s "\n"), sizeof(s "\n") - 1)
#define HASH_ADDR(addr) (unsigned long) (addr) % __ASAN_HASH_SIZE
#define DIV_CEIL(x, y) (((x) + (y) - 1) / (y))

typedef struct __asan_metadatum {
  void *allocated_page_start; // ガードページも含む
  void *begin;                // 有効アドレスの先頭
  int num_pages;              // ガードページも含む
  void *frames_alloc[__ASAN_MAX_FRAMES];
  void *frames_free[__ASAN_MAX_FRAMES];
  int frame_count_alloc;
  int frame_count_free;
  bool is_freed;
  struct __asan_metadatum *next;
} __asan_metadatum_t;
__asan_metadatum_t __asan_metadata[__ASAN_MAX_PAGES];

__asan_metadatum_t *__asan_rev[__ASAN_HASH_SIZE];

int __asan_allocated_index;

__asan_metadatum_t *find_asan_metadatum(void *ptr) {
  for (__asan_metadatum_t *p = __asan_rev[HASH_ADDR(ptr)]; ; p = p -> next) {
    if (p == NULL)
      return NULL;
    else if (p->begin == ptr)
      return p;
  }
}

void handle_sigsegv(int sig, siginfo_t *info, void *ucontext) {
  for (int i = 0; i < __asan_allocated_index; i++) {
    __asan_metadatum_t *metadatum = &__asan_metadata[i];
    if (metadatum->allocated_page_start <= info->si_addr &&
        info->si_addr < metadatum->allocated_page_start + __ASAN_PAGE_SIZE * metadatum->num_pages) {
      PUTS_STDERR("[chibicc-ASan]");
      
      if (info->si_addr < metadatum->allocated_page_start + __ASAN_PAGE_SIZE) {
        PUTS_STDERR("buffer-underflow");
      } else if (info->si_addr < metadatum->allocated_page_start + __ASAN_PAGE_SIZE * (metadatum->num_pages - 1)) {
        PUTS_STDERR("use-after-free");
      } else {
        PUTS_STDERR("buffer-overflow");
      }

      PUTS_STDERR("allocated at:");
      backtrace_symbols_fd(metadatum->frames_alloc, metadatum->frame_count_alloc, STDERR_FILENO);

      if (metadatum->is_freed) {
        PUTS_STDERR("freed at:");
        backtrace_symbols_fd(metadatum->frames_free, metadatum->frame_count_free, STDERR_FILENO);
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

void *asan_malloc(int size) {
  int num_valid_pages = DIV_CEIL(size, __ASAN_PAGE_SIZE);
  void *pages = mmap(NULL, __ASAN_PAGE_SIZE * (num_valid_pages + 2), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) {
    perror("mmap");
  }
  mprotect(pages + __ASAN_PAGE_SIZE, __ASAN_PAGE_SIZE * num_valid_pages, PROT_READ | PROT_WRITE);
  __asan_metadatum_t *metadatum = &__asan_metadata[__asan_allocated_index];
  metadatum->allocated_page_start = pages;
  metadatum->num_pages = num_valid_pages + 2;
  int frame_count = backtrace(metadatum->frames_alloc, __ASAN_MAX_FRAMES);
  metadatum->frame_count_alloc = frame_count;
  __asan_allocated_index++;

  void *ret = pages + __ASAN_PAGE_SIZE + (__ASAN_PAGE_SIZE - size % __ASAN_PAGE_SIZE) % __ASAN_PAGE_SIZE;
  metadatum->begin = ret;

  __asan_metadatum_t *next = __asan_rev[HASH_ADDR(ret)];
  __asan_rev[HASH_ADDR(ret)] = metadatum;
  __asan_rev[HASH_ADDR(ret)]->next = next;

  return ret;
}

void asan_free(void *ptr) {
  __asan_metadatum_t *metadatum = find_asan_metadatum(ptr);
  if (metadatum == NULL)
    abort();

  if (metadatum->is_freed) {
    PUTS_STDERR("[chibicc-ASan]");
    PUTS_STDERR("double-free");
    PUTS_STDERR("allocated at:");
    backtrace_symbols_fd(metadatum->frames_alloc, metadatum->frame_count_alloc, STDERR_FILENO);
    PUTS_STDERR("freed at:");
    backtrace_symbols_fd(metadatum->frames_free, metadatum->frame_count_free, STDERR_FILENO);
    abort();
  }

  int frame_count = backtrace(metadatum->frames_free, __ASAN_MAX_FRAMES);
  metadatum->frame_count_free = frame_count;
  if (mprotect(metadatum->allocated_page_start, __ASAN_PAGE_SIZE * metadatum->num_pages, PROT_NONE) == -1) {
    perror("mprotect");
  }
  metadatum->is_freed = true;
}

#endif