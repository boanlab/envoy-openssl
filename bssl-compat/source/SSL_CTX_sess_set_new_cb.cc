#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(SSL *ssl, SSL_SESSION *session)) {
  //// bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_sess_set_new_cb");
  ossl.ossl_SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
}

