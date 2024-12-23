#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" int SSL_CTX_set_tlsext_ticket_keys(SSL_CTX *ctx, const void *in, size_t len) {
  bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_tlsext_ticket_keys");
  return ossl.ossl_SSL_CTX_set_tlsext_ticket_keys(ctx, (void*)in, len);
}
