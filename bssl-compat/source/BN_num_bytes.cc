#include <openssl/bn.h>

extern "C" unsigned BN_num_bytes(const BIGNUM *bn) {
    return (BN_num_bits(bn) + 7) / 8;
}