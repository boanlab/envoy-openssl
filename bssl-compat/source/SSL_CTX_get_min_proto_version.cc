#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


extern "C" uint16_t SSL_CTX_get_min_proto_version(const SSL_CTX *ctx) {
  bssl_compat_info("[+]SSL_METHOD::SSL_CTX_get_min_proto_version");
  return ossl.ossl_SSL_CTX_get_min_proto_version((SSL_CTX*)ctx);
}

