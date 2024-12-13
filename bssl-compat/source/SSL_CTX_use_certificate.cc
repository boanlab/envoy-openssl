#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x509) {
  int ret = ossl.ossl_SSL_CTX_use_certificate(ctx, x509);
  //bssl_compat_info("[+]SSL_METHOD::SSL_CTX_use_certificate - value : %d", ret);
  return (ret == 1) ? 1 : 0;
}
