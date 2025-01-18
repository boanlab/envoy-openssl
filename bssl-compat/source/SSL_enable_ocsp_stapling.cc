#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" void SSL_enable_ocsp_stapling(SSL *ssl) {
  // bssl_compat_info("[+]SSL_METHOD::SSL_enable_ocsp_stapling");
  ossl.ossl_SSL_set_tlsext_status_type(ssl, ossl_TLSEXT_STATUSTYPE_ocsp);
}

