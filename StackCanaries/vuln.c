#include <stdio.h>
#include <stdlib.h>

void malicious() { printf("Code flow changed!!!\n"); }

int main(int argc, char **argv) {
  volatile int some_variable;
  char buffer[64];

  some_variable = 7;
  gets(buffer);

  if (some_variable != 7) {
    printf("Local variable modified!!!\n");
  }

  return 0;
}
