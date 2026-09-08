#ifndef BIP138_TEST_CRYPTO_H
#define BIP138_TEST_CRYPTO_H

#include "bip138.h"

/* PSA-backed callbacks (mbedtls) for the host tests. */
const bip138_crypto *test_crypto(void);
/* Callbacks that always fail, to check error propagation. */
const bip138_crypto *test_crypto_failing(void);
/* Callbacks whose random source is a seeded PRNG, for reproducible tests. */
const bip138_crypto *test_crypto_seeded(uint32_t seed);

#endif
