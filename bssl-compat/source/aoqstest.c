#include <stdio.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/types.h>
//#include <ossl.h>

void fetch_signature_algorithms(OSSL_PROVIDER *provider) {
   void *method = NULL;

   const OSSL_ALGORITHM *algorithms = OSSL_PROVIDER_query_operation(provider, 
                                                                  OSSL_OP_SIGNATURE,
                                                                  &method);
   
   if (algorithms) {
       printf("Available signature algorithms:\n");
       for (const OSSL_ALGORITHM *alg = algorithms; alg->algorithm_names != NULL; alg++) {
           printf("- %s\n", alg->algorithm_names);
       }

       // method 해제
       if (method)
           OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_SIGNATURE, method);
   } else {
       printf("No signature algorithms found\n");
       ERR_print_errors_fp(stderr);
   }
}

int OQSCALL() {
   // 모듈 경로 설정
   if (!OSSL_PROVIDER_set_default_search_path(NULL, "/home/boan/sds/bssl-compat-test/openssl-3.2.0/lib64/ossl-modules")) {
       printf("Failed to set module path\n");
       ERR_print_errors_fp(stderr);
       return 1;
   }

   // OpenSSL 라이브러리 컨텍스트 생성
   OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
   if (!ctx) {
       printf("Failed to create library context\n");
       ERR_print_errors_fp(stderr);
       return 1;
   }

   // 기본 provider 로드
   OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(ctx, "default");
   if (!defprov) {
       printf("Failed to load default provider\n");
       ERR_print_errors_fp(stderr);
       OSSL_LIB_CTX_free(ctx);
       return 1;
   }

   // OQS Provider 로드
   OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(ctx, "oqsprovider");
   if (!oqsprov) {
       printf("Failed to load oqsprovider\n");
       ERR_print_errors_fp(stderr);
       OSSL_PROVIDER_unload(defprov);
       OSSL_LIB_CTX_free(ctx);
       return 1;
   }

   // 서명 알고리즘 목록 조회
   fetch_signature_algorithms(oqsprov);

   // 정리
   OSSL_PROVIDER_unload(oqsprov);
   OSSL_PROVIDER_unload(defprov);
   OSSL_LIB_CTX_free(ctx);
   
   return 0;
}