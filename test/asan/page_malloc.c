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

int *wrapper() {
  return (int *) asan_page_malloc();
}

int main() {
  asan_init();
  int *p = wrapper();
  int *q = (int *) asan_page_malloc();
  int i;
  for (i = 0; i < 4096 / 4; i++) {
    p[i] = i;
    q[i] = i + 1;
  }
  ASSERT(p[42], 42);
  ASSERT(q[42], 43);
  asan_page_free(p);
  // asan_page_free(p);
  // f(p); // use-after-free
  p[1024] = 123;  // buffer-overflow
  // p[-1] = 123; // buffer-underflow
  return 0;
}