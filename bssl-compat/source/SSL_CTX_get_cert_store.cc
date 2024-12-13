#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <ossl.h>
#include "log.h"

// int print_ctx_info() {
//     EVP_MD_CTX* ctx = EVP_MD_CTX_new();
//     if (ctx) {
//         bssl_compat_info("Allocated EVP_MD_CTX size: %zu bytes\n", 
//                malloc_usable_size(ctx));  // malloc_usable_size는 glibc 확장
//         EVP_MD_CTX_free(ctx);
//     }
// }

extern "C" X509_STORE * SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
  bssl_compat_info("[+]SSL_METHOD::SSL_CTX_get_cert_store");
  return (X509_STORE*)ossl.ossl_SSL_CTX_get_cert_store((SSL_CTX*)ctx);
}