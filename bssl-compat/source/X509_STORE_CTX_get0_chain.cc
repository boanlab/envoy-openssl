#include <openssl/x509.h>
#include <ossl.h>
#include "log.h"


extern "C" STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx) {
  bssl_compat_info("[+]call SSL_METHOD::X509_STORE_CTX_get0_chain"); 
  return reinterpret_cast<STACK_OF(X509)*>(ossl_X509_STORE_CTX_get0_chain(ctx));
}
