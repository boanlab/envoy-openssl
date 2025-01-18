#include <openssl/x509.h>
#include <ossl.h>
#include "log.h"


extern "C" ASN1_OCTET_STRING *X509_EXTENSION_get_data( const X509_EXTENSION *ne) {
  // bssl_compat_info("[+]call SSL_METHOD::X509_EXTENSION_get_data"); 
  return ossl.ossl_X509_EXTENSION_get_data(const_cast<X509_EXTENSION*>(ne));
}
