#include "asan.h"

static int __asan_cmp(__asan_node_t *a, __asan_node_t *b) {
  return (a->key->raw_begin > b->key->raw_begin) - (a->key->raw_begin < b->key->raw_begin);
}

RB_HEAD(__asan_tree, __asan_node) __asan_head = RB_INITIALIZER(&__asan_head);
RB_PROTOTYPE(__asan_tree, __asan_node, entry, __asan_cmp);
RB_GENERATE(__asan_tree, __asan_node, entry, __asan_cmp);

static __asan_metadatum_t *find_asan_metadatum(void *ptr) {
  if (RB_EMPTY(&__asan_head)) {
    return NULL;
  }
  __asan_node_t find, *res_node;
  find.key = malloc(sizeof(__asan_metadatum_t));
  find.key->raw_begin = ptr;
  res_node = RB_NFIND(__asan_tree, &__asan_head, &find);  // lower_bound に相当

  free(find.key);

  __asan_metadatum_t *ret;
  if (res_node == NULL) {
    // 最大要素が答え
    ret = RB_MAX(__asan_tree, &__asan_head)->key;
  } else if (res_node->key->raw_begin == ptr) {
    // ptr 自身が先頭
    ret = res_node->key;
  } else {
    __asan_node_t *prev = RB_PREV(__asan_tree, &__asan_head, res_node);
    if (prev == NULL)
      return NULL;
    ret = prev->key;
  }

  if (ptr < ret->raw_begin || ptr >= ret->raw_begin + __ASAN_REDZONE_SIZE + ret->size + __ASAN_REDZONE_SIZE) {
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
    PUTS_STDERR("heap-buffer-overflow");
    break;
  case __AT_BUF:
    PUTS_STDERR("heap-buffer-underflow");
    break;
  case __AT_DF:
    PUTS_STDERR("double-free");
    break;
  default:
    abort();
  }
  PUTS_STDERR("-------- allocated at: --------");
  backtrace_symbols_fd(metadatum->frames_alloc, metadatum->frame_count_alloc, STDERR_FILENO);

  if (metadatum->is_freed) {
    PUTS_STDERR("-------- freed at: --------");
    backtrace_symbols_fd(metadatum->frames_free, metadatum->frame_count_free, STDERR_FILENO);
  }

  PUTS_STDERR("-------- traces: --------");
  int traces_start = (metadatum->trace_head + __ASAN_MAX_TRACES - metadatum->trace_count) % __ASAN_MAX_TRACES;
  for (int i = 0; i < metadatum->trace_count; i++) {
    fprintf(stderr, "ptr + %ld\n", metadatum->traces[(traces_start + i) % __ASAN_MAX_TRACES] - metadatum->begin);
  }
  exit(1);
}

void *asan_malloc(size_t size) {
  void *mem = malloc(__ASAN_REDZONE_SIZE + size + __ASAN_REDZONE_SIZE);
  if (mem == NULL) {
    perror("malloc");
  }

  __asan_metadatum_t *metadatum = malloc(sizeof(__asan_metadatum_t));
  metadatum->raw_begin = mem;
  metadatum->size = size;
  int frame_count = backtrace(metadatum->frames_alloc, __ASAN_MAX_FRAMES);
  metadatum->frame_count_alloc = frame_count;

  void *ret = mem + __ASAN_REDZONE_SIZE;
  metadatum->begin = ret;

  __asan_node_t *node = malloc(sizeof(__asan_node_t));
  node->key = metadatum;
  RB_INSERT(__asan_tree, &__asan_head, node);

  return ret;
}

void asan_free(void *ptr) {
  if (ptr == NULL)
    return;

  __asan_metadatum_t *metadatum = find_asan_metadatum(ptr);

  if (metadatum->is_freed) {
    show_asan_info_and_exit(metadatum, __AT_DF);
  }

  int frame_count = backtrace(metadatum->frames_free, __ASAN_MAX_FRAMES);
  metadatum->frame_count_free = frame_count;
  metadatum->is_freed = true;
}

void __trace_dereference(void *addr) {
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

    if (addr < metadatum->raw_begin + __ASAN_REDZONE_SIZE) {
      show_asan_info_and_exit(metadatum, __AT_BUF);
    } else if (addr >= metadatum->raw_begin + __ASAN_REDZONE_SIZE + metadatum->size) {
      show_asan_info_and_exit(metadatum, __AT_BOF);
    }
  }
}
