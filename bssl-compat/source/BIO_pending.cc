#include <openssl/bio.h>
#include <ossl.h>


extern "C" size_t BIO_pending(const BIO *bio) {
  if(use_ossl){
    return ossl_BIO_pending(const_cast<BIO*>(bio));
  }
  else {
    return bssl.bssl_BIO_pending(bio);
  }
}
