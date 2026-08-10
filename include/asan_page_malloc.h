#ifndef ASAN_PAGE_MALLOC_H
#define ASAN_PAGE_MALLOC_H

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>
#include <stdbool.h>
#include <sys/tree.h>

#define __ASAN_MAX_PAGES 1024
#define __ASAN_MAX_FRAMES 64
#define __ASAN_PAGE_SIZE sysconf(_SC_PAGE_SIZE)

#define PUTS_STDERR(s) write(STDERR_FILENO, (s "\n"), sizeof(s "\n") - 1)
#define DIV_CEIL(x, y) (((x) + (y) - 1) / (y))

typedef struct __asan_metadatum {
  void *allocated_page_start; // ガードページも含む
  void *begin;                // 有効アドレスの先頭
  int num_pages;              // ガードページも含む
  int size;
  void *frames_alloc[__ASAN_MAX_FRAMES];
  void *frames_free[__ASAN_MAX_FRAMES];
  int frame_count_alloc;
  int frame_count_free;
  bool is_freed;
  struct __asan_metadatum *next;
} __asan_metadatum_t;

typedef struct __asan_node {
  RB_ENTRY(__asan_node) entry;
  __asan_metadatum_t *key;
} __asan_node_t;

int __asan_cmp(__asan_node_t *a, __asan_node_t *b) {
  return (a->key->allocated_page_start > b->key->allocated_page_start) - (a->key->allocated_page_start < b->key->allocated_page_start);
}

RB_HEAD(__asan_tree, __asan_node) __asan_head = RB_INITIALIZER(&__asan_head);
RB_PROTOTYPE(__asan_tree, __asan_node, entry, __asan_cmp);
RB_GENERATE(__asan_tree, __asan_node, entry, __asan_cmp);

__asan_metadatum_t *find_asan_metadatum(void *ptr) {
  __asan_node_t find, *res_node;
  find.key = malloc(sizeof(__asan_metadatum_t));
  find.key->allocated_page_start = ptr;
  res_node = RB_NFIND(__asan_tree, &__asan_head, &find);  // lower_bound に相当

  __asan_metadatum_t *ret;
  if (res_node == NULL) {
    // 最大要素が答え
    ret = RB_MAX(__asan_tree, &__asan_head)->key;
  } else if (res_node->key->allocated_page_start == ptr) {
    // ptr 自身が先頭
    ret = res_node->key;
  } else {
    ret = RB_PREV(__asan_tree, &__asan_head, res_node)->key;
  }
  
  if (ptr < ret->begin || ptr >= ret->begin + ret->size)
    abort();

  return ret;
}

void handle_sigsegv(int sig, siginfo_t *info, void *ucontext) {
  __asan_node_t *node;
  RB_FOREACH(node, __asan_tree, &__asan_head) {
    __asan_metadatum_t *metadatum = node->key;
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
  act.sa_sigaction = handle_sigsegv;
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &act, NULL);
}

void *asan_malloc(int size) {
  int num_valid_pages = DIV_CEIL(size, __ASAN_PAGE_SIZE);
  void *pages = mmap(NULL, __ASAN_PAGE_SIZE * (num_valid_pages + 2), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) {
    perror("mmap");
  }
  mprotect(pages + __ASAN_PAGE_SIZE, __ASAN_PAGE_SIZE * num_valid_pages, PROT_READ | PROT_WRITE);

  __asan_metadatum_t *metadatum = malloc(sizeof(__asan_metadatum_t));
  metadatum->allocated_page_start = pages;
  metadatum->size = size;
  metadatum->num_pages = num_valid_pages + 2;
  int frame_count = backtrace(metadatum->frames_alloc, __ASAN_MAX_FRAMES);
  metadatum->frame_count_alloc = frame_count;
  
  void *ret = pages + __ASAN_PAGE_SIZE + (__ASAN_PAGE_SIZE - size % __ASAN_PAGE_SIZE) % __ASAN_PAGE_SIZE;
  metadatum->begin = ret;

  printf("malloc %p\n", metadatum);

  __asan_node_t *node = malloc(sizeof(__asan_node_t));
  node->key = metadatum;
  RB_INSERT(__asan_tree, &__asan_head, node);

  return ret;
}

void asan_free(void *ptr) {
  __asan_metadatum_t *metadatum = find_asan_metadatum(ptr);

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