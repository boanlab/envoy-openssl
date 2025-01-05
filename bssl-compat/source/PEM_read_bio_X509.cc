#include <openssl/pem.h>
#include <ossl/openssl/pem.h>
#include <ossl.h>
#include "log.h"


// X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
//   bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
//   return ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
// }

// X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
//     bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
    
//     // OpenSSL에서 에러 상태를 초기화
//     ERR_clear_error();
    
//     X509* cert = ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
//     if (cert == nullptr) {
//         unsigned long err = ERR_peek_last_error();
//         // PEM_R_NO_START_LINE 에러는 체인의 끝을 의미할 수 있으므로 특별 처리
//         if (ERR_GET_LIB(err) == ERR_LIB_PEM && 
//             ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
//             ERR_clear_error();
//             return nullptr;
//         }
//     }
//     return cert;
// }

// X509* PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
//     bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
//     ERR_clear_error();  // 시작 전 에러 상태 초기화
    
//     X509* cert = ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
//     if (cert == nullptr) {
//         unsigned long err = ERR_peek_last_error();
//         // PEM_R_NO_START_LINE은 정상적인 체인 끝을 의미할 수 있음
//         if (ERR_GET_LIB(err) == ERR_LIB_PEM && 
//             ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
//             ERR_clear_error();
//             return nullptr;
//         }
//         // 다른 에러의 경우 로깅
//         char err_buf[256];
//         ERR_error_string_n(err, err_buf, sizeof(err_buf));
//         bssl_compat_info("[-]SSL_METHOD::PEM_read_bio_X509 error: %s", err_buf);
//     } else {
//         // 성공적으로 인증서를 읽었을 때
//         bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509 - cert loaded");
        
//         // 인증서 참조 카운트 관리 (필요한 경우)
//         X509_up_ref(cert);
//     }
    
//     return cert;
// }
X509* PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
    bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509");
    
    X509* cert = ossl.ossl_PEM_read_bio_X509(bp, x, cb, u);
    
    if (cert == nullptr) {
        unsigned long err = ERR_peek_last_error();
        int lib = ERR_GET_LIB(err);
        int reason = ERR_GET_REASON(err);
        
        bssl_compat_info("[-]PEM_read_bio_X509 error details - lib: %d, reason: %d", lib, reason);
        
        if (lib == ERR_LIB_PEM && reason == PEM_R_NO_START_LINE) {
            bssl_compat_info("[+]End of chain detected (PEM_R_NO_START_LINE)");
            //ERR_clear_error();
            return nullptr;
        }
        
        // Get detailed error message
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        bssl_compat_info("[-]Detailed PEM error: %s", err_buf);
        
        // Print entire error queue
        bssl_compat_info("[-]Full error queue:");
        ossl.ossl_ERR_print_errors_cb([](const char *str, size_t len, void *ctx) -> int {
            bssl_compat_info("[-]Error: %.*s", (int)len, str);
            return 1;
        }, nullptr);
        
    } else {
        bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509 - cert loaded");
        
        // Only increase reference count if we're not passing ownership
        if (x == nullptr) {
            X509_up_ref(cert);
        }
    }
    
    return cert;
}