# bip138

[![CI](https://github.com/odudex/bip138/actions/workflows/ci.yml/badge.svg)](https://github.com/odudex/bip138/actions/workflows/ci.yml)

A small C implementation of [BIP138](https://github.com/bitcoin/bips/pull/1951), the Compact Encryption Scheme for Non-seed Wallet Data. It encrypts wallet metadata such as output descriptors and wallet policies to the public keys already present in the descriptor, so any cosigner can open the backup with nothing but their xpub.

The library implements version 1 of the format with ChaCha20-Poly1305. It is written in C99 for embedded targets: no allocation, no global state, and no dependencies.

## Design

- **Caller-supplied crypto.** A `bip138_crypto` struct carries four callbacks: SHA-256, ChaCha20-Poly1305 seal and open, and a CSPRNG. The library never links a crypto library of its own, so it drops into any project that already has one (mbedtls, PSA, libsodium, OpenSSL).
- **Caller-provided buffers.** Every function writes into memory the caller owns and returns `BIP138_ERR_SIZE` when it is too small. `bip138_encrypt_size`, `bip138_plaintext_size` and `bip138_plaintext_max` give the bounds up front. Parsed containers and decoded items are views into the caller's buffers.
- **Validated framing and strings.** String items are checked for valid UTF-8 during plaintext encoding and decoding. Unknown content types below `0x80` are skipped by the item iterator, including in backups containing only unknown items. Size helpers return zero for invalid or unrepresentable sizes; AEAD operations enforce the RFC 8439 plaintext limit.
- **Deterministic encryption on demand.** `bip138_encrypt_ex` accepts an explicit nonce and decoy list, which is how the test suite reproduces the BIP's vectors bit for bit. `bip138_encrypt` draws both from the CSPRNG.
- **No key exclusion policy beyond the BIP.** The BIP341 NUMS key is dropped from every recipient set. Excluding further publicly known keys is the caller's decision.

## Usage

```c
#include "bip138.h"

const bip138_crypto *crypto = my_crypto_callbacks();
uint8_t keys[2 * BIP138_KEY_LEN];   /* x-only keys of the descriptor's xpubs */

bip138_item item = {
    {BIP138_CONTENT_BIP, BIP138_BIP_DESCRIPTOR, NULL, 0},
    (const uint8_t *)descriptor, strlen(descriptor)};
size_t pt_len = bip138_plaintext_size(&item, 1, 0);
uint8_t *pt = malloc(pt_len);
bip138_plaintext_encode(&item, 1, 0, pt, pt_len, &pt_len);

size_t cap = bip138_encrypt_size(bip138_secret_bucket(2), NULL, 0, pt_len);
uint8_t *blob = malloc(cap);
size_t blob_len;
bip138_encrypt(crypto, keys, 2, NULL, 0, pt, pt_len, blob, cap, &blob_len);

/* Later, with one candidate key. */
bip138_container cont;
bip138_parse(blob, blob_len, &cont);
size_t out_cap = bip138_plaintext_max(&cont); /* 0: no room for the tag */
uint8_t *out = malloc(out_cap);
size_t out_len;
if (out_cap && bip138_decrypt(crypto, &cont, keys, 1, out, out_cap, &out_len,
                              NULL) == BIP138_OK) {
  bip138_item_iter it;
  bip138_item_iter_init(&it, out, out_len);
  while (bip138_item_next(&it, &item) == 1) {
    /* item.content and item.data */
  }
}
```

The container's derivation paths (`bip138_path_at`) and the BIP's 140 common paths (`bip138_common_path`) tell a wallet which xpubs to derive as decryption candidates. `bip138_decrypt` accepts any number of candidate keys and reports which one opened the payload.

## Building

As an ESP-IDF component the directory registers itself through its `CMakeLists.txt`; add `bip138` to the consumer's `REQUIRES`. Outside ESP-IDF the same file builds a static library (`add_subdirectory`, target `bip138`).

Host tests need `libmbedcrypto` (mbedtls 2.28 or later with PSA):

```sh
make run                       # optimised build, all three suites
make clean && make DEBUG=1 run # ASan + UBSan
make check32                   # compile-only 32-bit check (GCC multilib headers)
```

CI runs the three suites with GCC and Clang, optimised and under sanitizers, plus the 32-bit check, the CMake build, clang-format, and a check that `test/vectors.h` matches `test/vectors/*.json`.

## Test vectors

The regression suite covers short derivation paths, overflowing counts and sizes, unknown-only payloads, and UTF-8 boundaries and malformed strings. Run it with sanitizers to check buffer boundaries.

`test/vectors/*.json` are copied unchanged from the BIP's `bip-0138/test_vectors` directory (branch `encrypted_descriptor` of the author's fork, commit `5d441163`). `test/gen_vectors.py` converts them into the committed `test/vectors.h` so the tests need neither Python nor a JSON parser; run `make vectors` after updating the JSON files. `keys_types.json` covers descriptor key expressions, which need a descriptor parser and are therefore exercised by the consuming project rather than here.

## License

MIT. The test vectors are part of the BIP and carry its BSD-2-Clause license.
