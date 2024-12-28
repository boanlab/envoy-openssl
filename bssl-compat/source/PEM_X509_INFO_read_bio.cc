#include <openssl/pem.h>
#include <openssl/evp.h>
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
  struct sigaction sa;
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_sigaction = signal_handler;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);  // SIGSEGV Handler
  sigaction(SIGABRT, &sa, NULL);  // SIGABRT Handler
  if (!bp) return nullptr;
  bssl_compat_info("[+]SSL_METHOD::PEM_X509_INFO_read_bio-begin");

  // 스택 생성/재사용 로직 수정
  STACK_OF(X509_INFO)* ret = nullptr;
  if (sk != nullptr) {
    ret = sk;
  } else {
    ret = sk_X509_INFO_new_null(); 
    if (!ret) return nullptr;
  }
  bssl_compat_info("[+]SSL_METHOD::PEM_X509_INFO_read_bio-stack created: %p", (void*)ret);


  char *name = nullptr, *header = nullptr;
  unsigned char *data = nullptr;
  const unsigned char *p;
  long len = 0;

  int result = ossl.ossl_PEM_read_bio(bp, &name, &header, &data, &len);
  if (result <= 0) {
    sk_X509_INFO_free(ret);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return nullptr;
  }

  X509_INFO* xi = static_cast<X509_INFO*>(OPENSSL_malloc(sizeof(X509_INFO)));
  if (!xi) {
    sk_X509_INFO_free(ret);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return nullptr;
  }

  std::memset(xi, 0, sizeof(X509_INFO));
  p = data;

  if (strcmp(name, "CERTIFICATE") == 0) {
    bssl_compat_info("[+]PEM_X509_INFO_read_bio - Processing certificate");
    // OpenSSL의 X509를 BoringSSL의 X509로 변환
    X509* cert = ossl.ossl_d2i_X509(nullptr, &p, len);
    if (cert) {
      xi->x509 = cert;
      // 스택에 추가하기 전에 reference count 증가
      X509_up_ref(cert);
      if (!sk_X509_INFO_push(ret, xi)) {
        X509_INFO_free(xi);
        sk_X509_INFO_free(ret);
        ret = nullptr;
      }
    } else {
      X509_INFO_free(xi);
    }
  }

  OPENSSL_free(name);
  OPENSSL_free(header);
  OPENSSL_free(data);
  
  bssl_compat_info("[+]SSL_METHOD::PEM_X509_INFO_read_bio-end with result: %p", (void*)ret);
  return ret;
}
// extern "C" STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb, void *u) {
//   STACK_OF(X509_INFO) *saved {sk};
//   bssl_compat_info("[+]SSL_METHOD::PEM_X509_INFO_read_bio-begin");

//   auto ret {reinterpret_cast<STACK_OF(X509_INFO)*>(ossl.ossl_PEM_X509_INFO_read_bio(bp, nullptr, cb, u))};

//   if ((ret != nullptr) && (saved != nullptr)) {
//     for (size_t i = 0, max = sk_X509_INFO_num(ret); i < max; i++) {
//       sk_X509_INFO_push(saved, sk_X509_INFO_value(ret, i));
//     }
//     sk_X509_INFO_free(ret);
//     ret = saved;
//   }

//   return ret;
// }