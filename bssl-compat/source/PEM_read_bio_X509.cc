#include <openssl/pem.h>
#include <ossl/openssl/pem.h>
#include <ossl.h>
#include "log.h"


X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
  bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
  return ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
}
