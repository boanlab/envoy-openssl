#include <openssl/pem.h>
#include <ossl.h>
#include "log.h"


/*
 * https://github.com/google/boringssl/blob/b9ec9dee569854ac3dee909b9dfe8c1909a6c751/include/openssl/pem.h#L350
 * https://www.openssl.org/docs/man3.0/man3/PEM_X509_INFO_read_bio.html
 * 
 * Note that the BoringSSL and OpenSSL versions of PEM_X509_INFO_read_bio() have
 * slightly different behaviour in the case where an error occurs *and* a non-null
 * |sk| value was passed in.
 */
extern "C" STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb, void *u) {
  if (!bp) return nullptr;
  //bssl_compat_info("[+]SSL_METHOD::PEM_X509_INFO_read_bio-1");

  STACK_OF(X509_INFO)* ret = sk ? sk : sk_X509_INFO_new_null();
  if (!ret) return nullptr;

  char *name = nullptr, *header = nullptr;
  unsigned char *data = nullptr;
  const unsigned char *p;
  long len = 0;

  int result = ossl.ossl_PEM_read_bio(bp, &name, &header, &data, &len);
  if (result <= 0) {
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return ret;
  }
  bssl::UniquePtr<X509_INFO> xi(static_cast<X509_INFO*>(OPENSSL_malloc(sizeof(X509_INFO))));
  if (xi) {
    memset(xi.get(), 0, sizeof(X509_INFO));
    p = data;
    if (strcmp(name, "CERTIFICATE") == 0) {
      xi->x509 = ossl.ossl_d2i_X509(nullptr, &p, len);
    } else if (strcmp(name, "X509 CRL") == 0) {
      xi->crl = ossl.ossl_d2i_X509_CRL(nullptr, &p, len);
    }

    if (xi->x509 || xi->crl) {
      if (sk_X509_INFO_push(ret, xi.get())) {
        xi.release();
      }
    }
  }

  OPENSSL_free(name);
  OPENSSL_free(header);
  OPENSSL_free(data);

  return ret;
}