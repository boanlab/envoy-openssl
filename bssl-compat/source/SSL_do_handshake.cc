#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include "ossl.h"
// #include "log.h"

extern "C" int SSL_do_handshake(SSL *ssl) {
    // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Starting SSL handshake");
    
    // 핸드셰이크 전 SSL 상태 로깅
    // long ssl_mode = ossl.ossl_SSL_get_mode(ssl);
    // int ssl_state = ossl.ossl_SSL_get_state(ssl);
    // bssl_compat_info("SSL Mode: %ld, State: %d", ssl_mode, ssl_state);
    
    // 현재 사용 중인 인증서 검증
    // X509* cert = SSL_get_certificate(ssl);
    // if (cert) {
        // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Checking certificate");
        
        // ASN.1 구조 세부 검사
        // unsigned char *buf = nullptr;
        // int len = i2d_X509(cert, &buf);
        // if (len < 1) {
        //     return 0;
        // }

        // // X.509 버전 정보 출력
        // long version = ossl_X509_get_version(cert);
        // // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - X.509 version: %ld", version);
        
        // // ASN.1 패딩 검사
        // const unsigned char* p = buf;
        // long length = 0;
        // int type = 0;
        // int xclass = 0;
        // int tag = 0;
        
        // // X.509 구조체의 TBSCertificate 부분 디코딩
        // ossl_X509_CINF *cinf = ossl.ossl_d2i_X509_CINF(NULL, &p, len);
        // if (!cinf) {
        //     // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Failed to decode TBSCertificate");
        //     //OPENSSL_free(buf);
        //     //return 0;
        // }
        // ossl_X509_CINF_free(cinf);
        // OPENSSL_free(buf);

        // Subject가 비어있는 문제 확인
        // X509_NAME* subject = X509_get_subject_name(cert);
        // char subject_str[256] = {0};
        // X509_NAME_oneline(subject, subject_str, sizeof(subject_str));
        // if (strlen(subject_str) == 0) {
        //     // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Warning: Empty subject field");
        // }
        // // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Certificate Subject: %s", subject_str);
        
        // // Issuer 정보 확인
        // char issuer[256] = {0};
        // X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        // // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Certificate Issuer: %s", issuer);

        // // 시리얼 넘버 출력
        // ASN1_INTEGER* serial = X509_get_serialNumber(cert);
        // BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
        // char* serial_str = BN_bn2hex(bn);
        // // // bssl_compat_info("[+]SSL_METHODS::SSL_do_handshake - Certificate Serial: %s", serial_str);
        // OPENSSL_free(serial_str);
        // BN_free(bn);
    // }
    
    // 원본 함수 호출
    int result = ossl.ossl_SSL_do_handshake(ssl);
    
    return result;
}