#include "asan.h"

static int __asan_cmp(__asan_node_t *a, __asan_node_t *b) {
  return (a->key->allocated_page_start > b->key->allocated_page_start) - (a->key->allocated_page_start < b->key->allocated_page_start);
}

RB_HEAD(__asan_tree, __asan_node) __asan_head = RB_INITIALIZER(&__asan_head);
RB_PROTOTYPE(__asan_tree, __asan_node, entry, __asan_cmp);
RB_GENERATE(__asan_tree, __asan_node, entry, __asan_cmp);

static __asan_metadatum_t *find_asan_metadatum(void *ptr) {
  if (RB_EMPTY(&__asan_head)) {
    return NULL;
  }
  __asan_node_t find, *res_node;
  find.key = mmap(NULL, __ASAN_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  find.key->allocated_page_start = ptr;
  res_node = RB_NFIND(__asan_tree, &__asan_head, &find);  // lower_bound に相当

  munmap(find.key, __ASAN_PAGE_SIZE);

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

  if (ptr < ret->allocated_page_start || ptr >= ret->allocated_page_start + __ASAN_PAGE_SIZE * (ret->num_pages)) {
    return NULL;
  }

  return ret;
}

static void handle_sigsegv(int sig, siginfo_t *info, void *ucontext) {
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

      PUTS_STDERR("traces:");
      int traces_start = (metadatum->trace_head + __ASAN_MAX_TRACES - metadatum->trace_count) % __ASAN_MAX_TRACES;
      for (int i = 0; i < metadatum->trace_count; i++) {
        fprintf(stderr, "%ld\n", metadatum->traces[(traces_start + i) % __ASAN_MAX_TRACES] - metadatum->begin);
      }
      _exit(sig + 128);
    }
  }

  PUTS_STDERR("Segmentation fault (chibicc)");
  _exit(sig + 128);
}

__attribute__((constructor))
static void asan_init() {
  struct sigaction act = { 0 };
  sigemptyset(&act.sa_mask);
  act.sa_sigaction = handle_sigsegv;
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &act, NULL);
}

void *asan_malloc(size_t size) {
  int num_valid_pages = DIV_CEIL(size, __ASAN_PAGE_SIZE);
  void *pages = mmap(NULL, __ASAN_PAGE_SIZE * (num_valid_pages + 2), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pages == MAP_FAILED) {
    perror("mmap");
  }
  mprotect(pages + __ASAN_PAGE_SIZE, __ASAN_PAGE_SIZE * num_valid_pages, PROT_READ | PROT_WRITE);

  char *heap_for_metadata = mmap(NULL, __ASAN_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  __asan_metadatum_t *metadatum = (__asan_metadatum_t *) heap_for_metadata;
  metadatum->allocated_page_start = pages;
  metadatum->size = size;
  metadatum->num_pages = num_valid_pages + 2;
  int frame_count = backtrace(metadatum->frames_alloc, __ASAN_MAX_FRAMES);
  metadatum->frame_count_alloc = frame_count;

  void *ret = pages + __ASAN_PAGE_SIZE + (__ASAN_PAGE_SIZE - size % __ASAN_PAGE_SIZE) % __ASAN_PAGE_SIZE;
  metadatum->begin = ret;

  __asan_node_t *node = (__asan_node_t *) (heap_for_metadata + sizeof(__asan_metadatum_t));
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
    _exit(128 + SIGABRT);
  }

  int frame_count = backtrace(metadatum->frames_free, __ASAN_MAX_FRAMES);
  metadatum->frame_count_free = frame_count;
  if (mprotect(metadatum->allocated_page_start, __ASAN_PAGE_SIZE * metadatum->num_pages, PROT_NONE) == -1) {
    perror("mprotect");
  }
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
  }
}
