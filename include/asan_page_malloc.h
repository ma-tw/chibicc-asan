#ifndef ASAN_PAGE_MALLOC_H
#define ASAN_PAGE_MALLOC_H

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>

void *asan_page_malloc() {
  void *ret = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ret == MAP_FAILED) {
    perror("mmap");
  }
  return ret; 
}

void asan_page_free(void *p) {
  if (mprotect(p, 4096, PROT_NONE) == -1) {
    perror("mprotect");
  }
}

#endif