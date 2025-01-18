#include <openssl/pem.h>
#include <ossl.h>
#include "log.h"


RSA *PEM_read_bio_RSAPrivateKey(BIO *out, RSA **x, pem_password_cb *cb, void *u) {
  // FIXME: Reimplement with: https://www.openssl.org/docs/man3.0/man3/OSSL_DECODER_from_bio.html
  // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_RSAPrivateKey");
  return ossl.ossl_PEM_read_bio_RSAPrivateKey(out, x, cb, u);
}