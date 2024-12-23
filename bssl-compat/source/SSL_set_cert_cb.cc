#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"

extern "C" void SSL_set_cert_cb(SSL *ssl, int (*cb)(SSL *ssl, void *arg), void *arg) {
  bssl_compat_info("[+]SSL_METHOD::SSL_set_cert_cb");
  ossl.ossl_SSL_set_cert_cb(ssl, cb, arg);
}