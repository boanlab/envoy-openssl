#include <openssl/pem.h>
#include <ossl.h>
#include "log.h"

extern "C" X509 *PEM_read_bio_X509_AUX(BIO *out, X509 **x, pem_password_cb *cb, void *u) {
  // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509_AUX");
  return ossl.ossl_PEM_read_bio_X509_AUX(out, x, cb, u);
}

// PEM_read_bio_X509_AUX.cc
// X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
//     // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509_AUX");
    
//     // OpenSSL에서 에러 상태를 초기화
//     ERR_clear_error();
    
//     X509* cert = ossl.ossl_PEM_read_bio_X509_AUX(bp, x, cb, u);
//     if (cert != nullptr) {
//         // 성공적으로 읽었을 때 추가적인 속성 설정이 필요하다면 여기서 처리
//         // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509_AUX - success");
//     }
//     return cert;
// }

// X509* PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
//     // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509_AUX");
//     //ERR_clear_error();
    
//     X509* cert = ossl.ossl_PEM_read_bio_X509_AUX(bp, x, cb, u);
//     if (cert != nullptr) {
//         // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_X509_AUX - success");
//         // 참조 카운트 관리
//         X509_up_ref(cert);
//     } else {
//         unsigned long err = ERR_peek_last_error();
//         char err_buf[256];
//         ERR_error_string_n(err, err_buf, sizeof(err_buf));
//         // // bssl_compat_info("[-]SSL_METHOD::PEM_read_bio_X509_AUX error: %s", err_buf);
//     }
    
//     return cert;
// }