#include <openssl/digest.h>
#include <ossl.h>
#include "log.h"

#define EVP_MD_CTX_SIZE 80

extern "C" int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx) {
  // bssl_compat_info("[+]BSSL_METHOS::EVP_MD_CTX_cleanup() implemented other functions..");
  unsigned char *p = (unsigned char *)ctx;
  for (size_t i = 0; i < EVP_MD_CTX_SIZE; i++) {
        p[i] = 0;
  }

  memset(ctx, 0, EVP_MD_CTX_SIZE);
  return 1;
}