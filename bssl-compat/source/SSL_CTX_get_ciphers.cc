#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx) {
  bssl_compat_info("[+]SSL_METHOD::SSL_CTX_get_ciphers");
  return (STACK_OF(SSL_CIPHER)*)ossl.ossl_SSL_CTX_get_ciphers(ctx);
}
