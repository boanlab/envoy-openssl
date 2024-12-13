#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"

extern "C" {
  __attribute__((weak)) void SSL_CTX_set_reverify_on_resume(SSL_CTX *ctx, int enabled) {
  //ctx->reverify_on_resume = !!enabled;
  bssl_compat_info("[-] SSL_CTX_set_reverify_on_resume() is not implemented");
  }
}  