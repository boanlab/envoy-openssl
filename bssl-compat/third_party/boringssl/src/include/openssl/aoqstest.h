#include <openssl/types.h>

#ifndef OPENSSL_OQS_API_H
#define OPENSSL_OQS_API_H

#ifdef __cplusplus
extern "C" {
#endif

void fetch_signature_algorithms(OSSL_PROVIDER *provider);
int OQSCALL(void);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_OQS_API_H */

