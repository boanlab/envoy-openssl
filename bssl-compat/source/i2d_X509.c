#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


/*
 * On error, it returns a negative value. On success, it returns the length of
 * the result and outputs it via outp as follows:
 * 
 * If outp is NULL, the function writes nothing. This mode can be used to size
 * buffers. 
 * 
 * If outp is non-NULL but *outp is NULL, the function sets *outp to a newly
 * allocated buffer containing the result. The caller is responsible for
 * releasing *outp with OPENSSL_free. This mode is recommended for most callers.
 * 
 * If outp and *outp are non-NULL, the function writes the result to *outp,
 * which must have enough space available, and advances *outp just past the
 * output.
 */
// int i2d_X509(X509 *x509, uint8_t **outp) {
//   // bssl_compat_info("[+]BIO_METHOD::i2d_X509");
//   ossl_BIO *bio = ossl.ossl_BIO_new(ossl.ossl_BIO_s_mem());
//   int length = -1;
//   char *buf = NULL;

//   if (ossl.ossl_i2d_X509_bio(bio, x509)) { // 1=success, 0=failure
//     length = ossl.ossl_BIO_get_mem_data(bio, &buf);
//     // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - success - length: %d", length);

//     if (outp) {
//       if (*outp == NULL) {
//         *outp = ossl.ossl_OPENSSL_memdup(buf, length);
//       }
//       else {
//         ossl.ossl_OPENSSL_strlcpy((char*)*outp, buf, length);
//       }
//     }
//   } else {
//     // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - failed");
//   }

//   // 실제 데이터 검증
//   int found_padding = 0;
//   int padding_start = -1;
//   int consecutive_zeros = 0;

//   for (int i = 0; i < length; i++) {
//       if (buf[i] == 0x00) {
//           consecutive_zeros++;
//           if (consecutive_zeros >= 3 && !found_padding) {  // 3개 이상 연속된 0 발견
//               found_padding = 1;
//               padding_start = i - consecutive_zeros + 1;
//               // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Found potential zero-padding starting at byte: %d", padding_start);
//           }
//       } else {
//           if (consecutive_zeros >= 3) {
//               // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Zero sequence ended at byte: %d, length: %d", i, consecutive_zeros);
//           }
//           consecutive_zeros = 0;
//       }
      
//       // 특정 바이트 범위 상세 출력
//       if (i >= 500 && i <= 515) {
//           // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Byte %d: 0x%02X", i, buf[i]);
//       }
//   }

//   if (found_padding) {
//       // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Certificate data may be corrupted with zero-padding");
//   }

//   ossl.ossl_BIO_free(bio);

//   return length;
// }

#define X509_MAX_CERT_SIZE 16384  // 일반적인 인증서 최대 크기 (16KB)

int i2d_X509(X509 *x509, uint8_t **outp) {
    // bssl_compat_info("[+]BIO_METHOD::i2d_X509");
    
    if (!x509) {
        // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Invalid X509 certificate");
        return -1;
    }

    ossl_BIO *bio = ossl.ossl_BIO_new(ossl.ossl_BIO_s_mem());
    if (!bio) {
        // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Failed to create BIO");
        return -1;
    }

    int length = -1;
    char *buf = NULL;

    // i2d_X509_bio를 사용하여 인증서를 BIO에 쓰기
    if (!ossl.ossl_i2d_X509_bio(bio, x509)) {
        // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Failed to write certificate to BIO");
        ossl.ossl_BIO_free(bio);
        return -1;
    }

    // BIO에서 데이터 가져오기
    length = ossl.ossl_BIO_get_mem_data(bio, &buf);
    
    // 길이 유효성 검사
    if (length <= 0 || length > X509_MAX_CERT_SIZE) {
        // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Invalid certificate length: %d", length);
        ossl.ossl_BIO_free(bio);
        return -1;
    }

    if (outp) {
        if (*outp == NULL) {
            *outp = (uint8_t *)ossl.ossl_OPENSSL_malloc(length);
            if (!*outp) {
                // bssl_compat_info("[+]BIO_METHOD::i2d_X509 - Memory allocation failed");
                ossl.ossl_BIO_free(bio);
                return -1;
            }
        }
        memcpy(*outp, buf, length);
    }

    ossl.ossl_BIO_free(bio);
    return length;
}