#include <openssl/asn1.h>
#include <ossl.h>
#include "log.h"


void ASN1_TIME_free(ASN1_TIME *s) {
  bssl_compat_info("[+]SSL_METHOD::ASN1_TIME_free");
  ossl.ossl_ASN1_TIME_free(s);
}
