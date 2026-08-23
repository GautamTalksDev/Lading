#include <openssl/ssl.h>
#include <stdio.h>
int main(void) {
  OPENSSL_init_ssl(0, NULL);
  puts("LADING_SSL_MARKER");
  return 0;
}
