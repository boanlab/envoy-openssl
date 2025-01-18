#include <openssl/pem.h>
#include <ossl/openssl/pem.h>
#include <ossl.h>
#include "log.h"


X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
  // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
  return ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
}

// X509* PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
//     // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
    
//     X509* cert = ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
    
//     if (cert == nullptr) {
//         unsigned long err = ERR_peek_last_error();
//         int lib = ERR_GET_LIB(err);
//         int reason = ERR_GET_REASON(err);
        
//         // bssl_compat_info("[-]PEM_read_bio_X509 error details - lib: %d, reason: %d", lib, reason);
        
//         if (lib == ERR_LIB_PEM && reason == PEM_R_NO_START_LINE) {
//             // bssl_compat_info("[+]End of chain detected (PEM_R_NO_START_LINE)");
//             ERR_clear_error();
//             return nullptr;
//         }
        
//         // Get detailed error message
//         char err_buf[256];
//         ERR_error_string_n(err, err_buf, sizeof(err_buf));
//         // bssl_compat_info("[-]Detailed PEM error: %s", err_buf);
        
//         // Print entire error queue
//         // bssl_compat_info("[-]Full error queue:");
//         ossl.ossl_ERR_print_errors_cb([](const char *str, size_t len, void *ctx) -> int {
//             // bssl_compat_info("[-]Error: %.*s", (int)len, str);
//             return 1;
//         }, nullptr);
        
//     } else {
//         // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509 - cert loaded");
        
//         // Only increase reference count if we're not passing ownership
//         if (x == nullptr) {
//             X509_up_ref(cert);
//         }
//     }
    
//     return cert;
// }