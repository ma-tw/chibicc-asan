#include "test.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void g(int *p) {
  p[0] = 0;
}

void f(int *p) {
  g(p);
}

int main() {
  int *p = malloc(50 * sizeof(int));
  int *q = malloc(50 * sizeof(int));
  printf("%p\n", p);
  int i;
  for (i = 0; i < 50; i++) {
    p[i] = i;
    q[i] = i + 1;
  }
  // ASSERT(p[42], 42);
  // ASSERT(q[42], 43);
  free(p);
  // f(p); // use-after-free
  // p[50] = 123;  // buffer-overflow
  // p[-1024] = 123; // buffer-underflow

  printf("OK\n");
  return 0;
}