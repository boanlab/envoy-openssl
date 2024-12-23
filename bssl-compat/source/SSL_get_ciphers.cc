#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *ssl) {
  bssl_compat_info("[+]SSL_METHOD::SSL_get_ciphers");
  return reinterpret_cast<STACK_OF(SSL_CIPHER)*>(ossl.ossl_SSL_get_ciphers(ssl));
}
