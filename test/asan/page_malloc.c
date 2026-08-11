#include "test.h"
#include "asan_page_malloc.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void g(int *p) {
  p[42] = 0;
}

void f(int *p) {
  g(p);
}

int main() {
  int *p = asan_malloc(4096 + 4);
  int *q = asan_malloc(4096);
  printf("%p\n", p);
  int i;
  for (i = 0; i < 4096 / 4; i++) {
    p[i] = i;
    q[i] = i + 1;
  }
  ASSERT(p[42], 42);
  ASSERT(q[42], 43);
  asan_free(p + 123);
  // f(p); // use-after-free
  // p[1025] = 123;  // buffer-overflow
  // p[-4096] = 123; // buffer-underflow
  return 0;
}