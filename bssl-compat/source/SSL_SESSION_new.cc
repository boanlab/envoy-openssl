#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


SSL_SESSION *SSL_SESSION_new(const SSL_CTX *ctx) {
  if(ctx) {
    bssl_compat_warn("%s() with non-null ctx not implemented", __func__);
  }
  // bssl_compat_info("[+]SSL_METHOD::SSL_SESSION_new");
  return ossl.ossl_SSL_SESSION_new();
}