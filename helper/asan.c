#include "asan.h"

static int asan_cmp(__asan_metadatum_t *a, __asan_metadatum_t *b) {
  return (a->raw_begin > b->raw_begin) - (a->raw_begin < b->raw_begin);
}

RB_HEAD(__asan_tree, __asan_metadatum) __asan_head = RB_INITIALIZER(&__asan_head);
RB_PROTOTYPE(__asan_tree, __asan_metadatum, entry, asan_cmp);
RB_GENERATE(__asan_tree, __asan_metadatum, entry, asan_cmp);

static __asan_metadatum_t *find_asan_metadatum(void *ptr) {
  if (RB_EMPTY(&__asan_head)) {
    return NULL;
  }
  __asan_metadatum_t find, *res_node;
  find.raw_begin = ptr;
  res_node = RB_NFIND(__asan_tree, &__asan_head, &find);  // lower_bound に相当

  __asan_metadatum_t *ret;
  if (res_node == NULL) {
    // 最大要素が答え
    ret = RB_MAX(__asan_tree, &__asan_head);
  } else if (res_node->raw_begin == ptr) {
    // ptr 自身が先頭
    ret = res_node;
  } else {
    ret = RB_PREV(__asan_tree, &__asan_head, res_node);
    if (ret == NULL)
      return NULL;
  }

  if (ptr < ret->raw_begin || ptr >= ret->raw_begin + ret->raw_size) {
    return NULL;
  }

  return ret;
}

__attribute__((noreturn))
static void show_asan_info_and_exit(__asan_metadatum_t *metadatum, __asan_type_t type) {
  PUTS_STDERR("======== [chibicc-ASan] ========");
  switch (type) {
  case __AT_UAF:
    PUTS_STDERR("use-after-free");
    break;
  case __AT_BOF:
    if (metadatum->region_kind == __ASAN_REGION_GLOBAL)
      PUTS_STDERR("global-buffer-overflow");
    else
      PUTS_STDERR("heap-buffer-overflow");
    break;
  case __AT_BUF:
    if (metadatum->region_kind == __ASAN_REGION_GLOBAL)
      PUTS_STDERR("global-buffer-underflow");
    else
      PUTS_STDERR("heap-buffer-underflow");
    break;
  case __AT_DF:
    PUTS_STDERR("double-free");
    break;
  default:
    abort();
  }
  if (metadatum->region_kind == __ASAN_REGION_GLOBAL) {
    fprintf(stderr, "global variable: %s\n", metadatum->name);
  } else {
    PUTS_STDERR("-------- allocated at: --------");
    backtrace_symbols_fd(metadatum->frames_alloc, metadatum->frame_count_alloc,
                         STDERR_FILENO);
  }

  if (metadatum->is_freed) {
    PUTS_STDERR("-------- freed at: --------");
    backtrace_symbols_fd(metadatum->frames_free, metadatum->frame_count_free, STDERR_FILENO);
  }

  PUTS_STDERR("-------- traces: --------");
  int traces_start = (metadatum->trace_head + __ASAN_MAX_TRACES - metadatum->trace_count) % __ASAN_MAX_TRACES;
  for (int i = 0; i < metadatum->trace_count; i++) {
    fprintf(stderr, "ptr + %ld\n",
            metadatum->traces[(traces_start + i) % __ASAN_MAX_TRACES] -
            metadatum->begin);
  }
  exit(1);
}

void *__asan_malloc(size_t size) {
  void *mem = malloc(__ASAN_REDZONE_SIZE + size + __ASAN_REDZONE_SIZE);
  if (mem == NULL) {
    perror("malloc");
  }

  __asan_metadatum_t *metadatum = calloc(1, sizeof(__asan_metadatum_t));
  metadatum->raw_begin = mem;
  metadatum->size = size;
  metadatum->raw_size = __ASAN_REDZONE_SIZE + size + __ASAN_REDZONE_SIZE;
  metadatum->region_kind = __ASAN_REGION_HEAP;
  int frame_count = backtrace(metadatum->frames_alloc, __ASAN_MAX_FRAMES);
  metadatum->frame_count_alloc = frame_count;

  void *ret = mem + __ASAN_REDZONE_SIZE;
  metadatum->begin = ret;

  RB_INSERT(__asan_tree, &__asan_head, metadatum);

  return ret;
}

void __asan_register_global(void *raw_begin, void *begin, size_t size,
                            size_t raw_size, const char *name) {
  __asan_metadatum_t *metadatum = calloc(1, sizeof(__asan_metadatum_t));
  if (metadatum == NULL) {
    perror("calloc");
    exit(1);
  }

  metadatum->raw_begin = raw_begin;
  metadatum->begin = begin;
  metadatum->size = size;
  metadatum->raw_size = raw_size;
  metadatum->region_kind = __ASAN_REGION_GLOBAL;
  metadatum->name = name;

  RB_INSERT(__asan_tree, &__asan_head, metadatum);
}

__asan_metadatum_t *__asan_quarantine[__ASAN_QUAR_SIZE];
int __asan_quar_head;

void __asan_free(void *ptr) {
  if (ptr == NULL)
    return;

  __asan_metadatum_t *metadatum = find_asan_metadatum(ptr);

  if (metadatum == NULL || metadatum->region_kind != __ASAN_REGION_HEAP) {
    PUTS_STDERR("======== [chibicc-ASan] ========");
    PUTS_STDERR("invalid-free");
    if (metadatum && metadatum->name)
      fprintf(stderr, "global variable: %s\n", metadatum->name);
    exit(1);
  }

  if (metadatum->is_freed) {
    show_asan_info_and_exit(metadatum, __AT_DF);
  }

  int frame_count = backtrace(metadatum->frames_free, __ASAN_MAX_FRAMES);
  metadatum->frame_count_free = frame_count;
  metadatum->is_freed = true;

  __asan_metadatum_t *tail = __asan_quarantine[__asan_quar_head];
  if (tail != NULL) {
    fprintf(stderr, "%p is actually freed\n", tail->begin);
    RB_REMOVE(__asan_tree, &__asan_head, tail);
    free(tail->raw_begin);
    free(tail);
  }
  __asan_quarantine[__asan_quar_head] = metadatum;
  __asan_quar_head = (__asan_quar_head + 1) % __ASAN_QUAR_SIZE;
}

void __asan_check(void *addr, size_t access_size) {
  __asan_metadatum_t *metadatum;
  if ((metadatum = find_asan_metadatum(addr)) != NULL) {
    metadatum->traces[metadatum->trace_head] = addr;
    metadatum->trace_head = (metadatum->trace_head + 1) % __ASAN_MAX_TRACES;

    if (metadatum->trace_count < __ASAN_MAX_TRACES) {
      metadatum->trace_count++;
    }

    if (metadatum->is_freed) {
      show_asan_info_and_exit(metadatum, __AT_UAF);
    }

    if (addr < metadatum->begin) {
      show_asan_info_and_exit(metadatum, __AT_BUF);
    }

    size_t offset = addr - metadatum->begin;
    if (offset >= metadatum->size || access_size > metadatum->size - offset) {
      show_asan_info_and_exit(metadatum, __AT_BOF);
    }
  }
}
