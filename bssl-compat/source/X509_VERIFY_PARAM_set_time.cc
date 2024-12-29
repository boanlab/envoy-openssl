#include <openssl/x509.h>
#include <ossl.h>


extern "C" void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, int64_t t) {
  return ossl.ossl_X509_VERIFY_PARAM_set_time(param, t);
}