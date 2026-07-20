#include "test.h"
#include "asan_page_malloc.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

void handle_sigsegv(int sig) {
  char msg[] = "ASan: heap-use-after-free detected\n";
  write(STDERR_FILENO, msg, sizeof(msg));
  _exit(1);
}

int main() {
  struct sigaction act = { 0 };
  sigemptyset(&act.sa_mask);
  act.sa_handler = handle_sigsegv;
  sigaction(SIGSEGV, &act, NULL);
  int *p = (int *) asan_page_malloc();
  int *q = (int *) asan_page_malloc();
  int i;
  for (i = 0; i < 4096 / 4; i++) {
    p[i] = i;
    q[i] = i + 1;
  }
  ASSERT(p[42], 42);
  ASSERT(q[42], 43);
  asan_page_free(p);
  p[42] = 0;
  return 0;
}