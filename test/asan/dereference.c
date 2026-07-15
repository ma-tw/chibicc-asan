#include "test.h"

typedef struct {
  int value;
} Data;

int main() {
  int values[2] = {};
  int *p = values;

  *p = 3;
  ASSERT(3, *p);

  p[1] = 5;
  ASSERT(5, p[1]);

  Data data = {};
  Data *data_ptr = &data;
  data_ptr->value = 7;
  ASSERT(7, data_ptr->value);

  printf("OK\n");
  return 0;
}
