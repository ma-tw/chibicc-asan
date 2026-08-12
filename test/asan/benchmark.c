#include <stdio.h>
#include <stdlib.h>
#include <time.h>

long long get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  return (long long) ts.tv_sec * 1000000000 + (long long) ts.tv_nsec;
}

#define MATRIX_SIZE 100 

void matmul(int **a, int **b, int **res) {
  for (int i = 0; i < MATRIX_SIZE; i++) {
    for (int j = 0; j < MATRIX_SIZE; j++) {
      int sum = 0;
      for (int k = 0; k < MATRIX_SIZE; k++) {
        sum += a[i][k] * b[k][j];
      }
      res[i][j] = sum;
    }
  }
}

int main() {
  long long start = get_time_ns();
  int **a = malloc(MATRIX_SIZE * sizeof(int *));
  for (int i = 0; i < MATRIX_SIZE; i++) {
    a[i] = malloc(MATRIX_SIZE * sizeof(int));
  }
  int **b = malloc(MATRIX_SIZE * sizeof(int *));
  for (int i = 0; i < MATRIX_SIZE; i++) {
    b[i] = malloc(MATRIX_SIZE * sizeof(int));
  }
  int **res = malloc(MATRIX_SIZE * sizeof(int *));
  for (int i = 0; i < MATRIX_SIZE; i++) {
    res[i] = malloc(MATRIX_SIZE * sizeof(int));
  }
  for (int i = 0; i < MATRIX_SIZE; i++) {
    for (int j = 0; j < MATRIX_SIZE; j++) {
      a[i][j] = i + j;
      b[i][j] = i - j;
    }
  }
  matmul(a, b, res);
  long long end = get_time_ns();
  printf("execution time: %lf ms\n", (double) (end - start) / 1000000);
}