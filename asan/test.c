#include "asan_page_malloc.h"

int main() {
  int *p = (int *) asan_malloc(100 * sizeof(int));
  p[100-1] = 32323;
  asan_free(p);
}