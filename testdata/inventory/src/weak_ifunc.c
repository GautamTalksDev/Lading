#include <stdio.h>
static int real_impl(void) { return 42; }
static void *resolver(void) { return (void *)real_impl; }
int resolved(void) __attribute__((ifunc("resolver")));
__attribute__((weak)) int weak_sym(void) { return 7; }
int main(void) {
  printf("LADING_WEAK_IFUNC %d %d\n", resolved(), weak_sym());
  return 0;
}
