#include <openssl/ssl.h> // boringssl 헤더 지정이 되어 있지 않음
#include <ossl.h>
#include "iana_2_ossl_names.h"
#include "log.h"

extern "C" int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {
  bssl_compat_info("[+]SSL_METHOD::SSL_CTX_set_ciphersuites - Cipher Suite string: %s", str);
  return ossl.ossl_SSL_CTX_set_ciphersuites(ctx, str);
}