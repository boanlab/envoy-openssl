#include <openssl/pool.h>
#include <openssl/mem.h>
#include "CRYPTO_BUFFER.h"
#include "log.h"


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/pool.h#L74
 */
void CRYPTO_BUFFER_free(CRYPTO_BUFFER *buf) {
  if (buf == NULL) {
    return;
  }
  bssl_compat_info("[+]BIO_METHOD::CRYPTO_BUFFER_free");
  OPENSSL_free(buf->data);
  OPENSSL_free(buf);
}
