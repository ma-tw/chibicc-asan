#include <stdio.h>

void __trace_malloc() {
  printf("malloc called\n");
}

void __trace_free() {
  printf("free called\n");
}
