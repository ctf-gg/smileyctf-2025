#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int (*print)(const char*) = puts;

void gadgets() {
  __asm__ __volatile__ (
    "pop %rcx;"
    "ret;"
  );
}

int gets(char* buf) {
  int n = read(0, buf, 700);
  if (n > 0) {
    buf[n-1] = 0;
  }
  return n;
}

int main() {
  char buf[32];
  setbuf(stdout, NULL);
  memset(buf, 0, 32);
  gets(buf);
  print(buf);
}
