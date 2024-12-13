#include <openssl/pem.h>
#include <ossl.h>
#include "log.h"


extern "C" X509_CRL *PEM_read_bio_X509_CRL(BIO *out, X509_CRL **x, pem_password_cb *cb, void *u) {
  //bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509_CRL");
  return ossl.ossl_PEM_read_bio_X509_CRL(out, x, cb, u);
}
