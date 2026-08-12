#include "test.h"
#include <stdlib.h>

int main() {
  int *p[100];
  for (int i = 0; i < 100; i++) {
    p[i] = malloc(100 * sizeof(int));
    p[i][i] = i;
    free(p[i]);
  }

  printf("OK\n");
}
