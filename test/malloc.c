#include "test.h"
#include <stdlib.h>

int main() {
  int *p = (int *) malloc(12);
  p[3] = 12;
  ASSERT(p[3], 12);
  free(p);

  printf("OK\n");
  return 0;
}
