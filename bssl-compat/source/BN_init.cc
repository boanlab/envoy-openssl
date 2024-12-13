#include <openssl/bn.h>
#include <ossl.h>
#include "log.h"

extern "C" {
  __attribute__((weak)) void BN_init(BIGNUM *bn) {
   //OPENSSL_memset(bn, 0, sizeof(BIGNUM));
   //bssl_compat_info("[-] BN_init() is not implemented");
 }
}