#include <openssl/crypto.h> 
#include <ossl.h>
#include "iana_2_ossl_names.h"

extern "C" const char* OpenSSL_version(int t) {
  return ossl.ossl_OpenSSL_version(t);
}
