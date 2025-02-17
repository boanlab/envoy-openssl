#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list) {
  // bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_client_CA_list");
  ossl.ossl_SSL_CTX_set_client_CA_list(ctx, (ossl_STACK_OF(ossl_X509_NAME)*)name_list);
}
