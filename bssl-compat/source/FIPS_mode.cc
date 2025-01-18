#include <openssl/crypto.h>
#include <ossl.h>
#include "log.h"


extern "C" int FIPS_mode(void) {
  // bssl_compat_info("[+]SSL_METHOD::FIPS_mode");
  return ossl.ossl_EVP_default_properties_is_fips_enabled(NULL);
}
