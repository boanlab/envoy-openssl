#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, const uint8_t **out, uint8_t *out_len, const uint8_t *in, unsigned in_len, void *arg), void *arg) {
  //bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_alpn_select_cb");
  ossl.ossl_SSL_CTX_set_alpn_select_cb(ctx, cb, arg);
}
