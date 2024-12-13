#include <openssl/pem.h>
#include <ossl/openssl/pem.h>
#include <ossl.h>
#include "log.h"


extern "C" int PEM_write_bio_X509(BIO *bp, X509 *x) {
  //bssl_compat_info("[+]SSL_METHOD::PEM_write_bio_X509");
  return ossl.ossl_PEM_write_bio_X509(bp, x);
}
