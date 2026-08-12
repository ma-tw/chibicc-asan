#ifndef __ASAN_H
#define __ASAN_H

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
#define __ASAN_MAX_TRACES 64
#define __ASAN_REDZONE_SIZE 64
#define __ASAN_QUAR_SIZE 16

#define PUTS_STDERR(s) write(STDERR_FILENO, (s "\n"), sizeof(s "\n") - 1)
#define DIV_CEIL(x, y) (((x) + (y) - 1) / (y))

typedef struct __asan_metadatum {
  RB_ENTRY(__asan_metadatum) entry;
  void *raw_begin;            // redzoneも含む
  void *begin;                // 有効アドレスの先頭
  int size;
  void *frames_alloc[__ASAN_MAX_FRAMES];
  void *frames_free[__ASAN_MAX_FRAMES];
  void *traces[__ASAN_MAX_TRACES];  // ring buffer
  int frame_count_alloc;
  int frame_count_free;
  int trace_head, trace_count;
  bool is_freed;
} __asan_metadatum_t;

typedef enum {
  __AT_UAF,
  __AT_BOF,
  __AT_BUF,
  __AT_DF,
} __asan_type_t;

void *__asan_malloc(size_t size);

void __asan_free(void *ptr);

void __trace_dereference(void *addr);

#endif
