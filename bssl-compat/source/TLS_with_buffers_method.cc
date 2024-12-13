#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" const SSL_METHOD *TLS_with_buffers_method(void) {
  bssl_compat_info("[+]call SSL_METHOD::TLS_with_buffers_method"); 
  return ossl.ossl_TLS_method();
}

