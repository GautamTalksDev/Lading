#include <stdio.h>
const char *lading_marker = "LADING_RODATA_MARKER";
int lading_export(int x) { return x + 1; }
int main(void) {
  puts(lading_marker);
  return lading_export(41);
}
