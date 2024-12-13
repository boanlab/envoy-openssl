#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*callback)(int ok, X509_STORE_CTX *store_ctx)) {
  //bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_verify");
  ossl.ossl_SSL_CTX_set_verify(ctx, mode, callback);
}
