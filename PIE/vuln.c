#include <stdio.h>

void vuln() {
  puts("It never gets old");
  char buffer[64];
  gets(buffer);
}

int main() {
  vuln();
  return 0;
}
