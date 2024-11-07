#include <ossl/openssl/provider.h>
#include <ossl.h>
#include <ossl/openssl/crypto.h>
#include <ossl/openssl/core_names.h>
#include <ossl/openssl/core_dispatch.h>
#include <ossl/openssl/params.h>
#include <ossl/openssl/err.h>
#include <ossl/openssl/types.h>

void fetch_signature_algorithms(ossl_OSSL_PROVIDER *provider) {
   int method = 0;

   const ossl_OSSL_ALGORITHM *algorithms = ossl_OSSL_PROVIDER_query_operation(provider, 
                                                                  ossl_OSSL_OP_SIGNATURE,
                                                                  &method);
   
   if (algorithms) {
       printf("Available signature algorithms:\n");
       for (const ossl_OSSL_ALGORITHM *alg = algorithms; alg->algorithm_names != NULL; alg++) {
           printf("- %s\n", alg->algorithm_names);
       }

       if (method)
           ossl_OSSL_PROVIDER_unquery_operation(provider, ossl_OSSL_OP_SIGNATURE, NULL);
   } else {
       printf("No signature algorithms found\n");
       ossl_ERR_print_errors_fp(stderr);
   }
}

extern "C" {
int OQSCALL() {
   // 환경 변수에서 모듈 경로 가져오기
   const char* module_path = getenv("OPENSSL_MODULES");
   if (!module_path) {
       module_path = OPENSSL_MODULES_DIR;  // CMake에서 정의된 기본 경로 사용
   }

   // 모듈 경로 설정
   if (!ossl_OSSL_PROVIDER_set_default_search_path(NULL, module_path)) {
       printf("Failed to set module path: %s\n", module_path);
       ossl_ERR_print_errors_fp(stderr);
       return 1;
   }

   // OpenSSL 라이브러리 컨텍스트 생성
   ossl_OSSL_LIB_CTX *ctx = ossl_OSSL_LIB_CTX_new();
   if (!ctx) {
       printf("Failed to create library context\n");
       ossl_ERR_print_errors_fp(stderr);
       return 1;
   }

   // 기본 provider 로드
   ossl_OSSL_PROVIDER *defprov = ossl_OSSL_PROVIDER_load(ctx, "default");
   if (!defprov) {
       printf("Failed to load default provider\n");
       ossl_ERR_print_errors_fp(stderr);
       ossl_OSSL_LIB_CTX_free(ctx);
       return 1;
   }

   // OQS Provider 로드
   ossl_OSSL_PROVIDER *oqsprov = ossl_OSSL_PROVIDER_load(ctx, "oqsprovider");
   if (!oqsprov) {
       printf("Failed to load oqsprovider\n");
       ossl_ERR_print_errors_fp(stderr);
       ossl_OSSL_PROVIDER_unload(defprov);
       ossl_OSSL_LIB_CTX_free(ctx);
       return 1;
   }

   // 서명 알고리즘 목록 조회
   fetch_signature_algorithms(oqsprov);

   // 정리
   ossl_OSSL_PROVIDER_unload(oqsprov);
   ossl_OSSL_PROVIDER_unload(defprov);
   ossl_OSSL_LIB_CTX_free(ctx);
   
   return 0;
}
}