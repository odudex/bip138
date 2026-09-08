#ifndef BIP138_INTERNAL_H
#define BIP138_INTERNAL_H

#include "bip138.h"
#include <stddef.h>
#include <stdint.h>

#define BIP138_TAG_DECRYPTION_SECRET "BIP138_DECRYPTION_SECRET"
#define BIP138_TAG_INDIVIDUAL_SECRET "BIP138_INDIVIDUAL_SECRET"

/* RFC 8439's plaintext limit, before the authentication tag. */
#define BIP138_MAX_PLAINTEXT_LEN ((UINT64_C(1) << 38) - 64)

/* Keep the comparison in the wire length's domain. On 32-bit targets every
 * size_t fits the RFC limit, but parsed CompactSize lengths can exceed it. */
static inline int bip138_plaintext_len_valid(uint64_t len) {
  return len <= BIP138_MAX_PLAINTEXT_LEN;
}

/* BIP341 NUMS point x-coordinate; never a recipient. */
extern const uint8_t bip138_nums_key[BIP138_KEY_LEN];

size_t bip138_varint_size(uint64_t value);
int bip138_varint_write(uint8_t *out, size_t out_cap, uint64_t value,
                        size_t *written);
/* Rejects non-minimal encodings. */
int bip138_varint_read(const uint8_t *buf, size_t len, uint64_t *value,
                       size_t *consumed);

int bip138_tagged_hash(const bip138_crypto *c, const char *tag,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32]);
/* Copies the sorted, deduplicated keys without the NUMS key into out. */
int bip138_keys_normalize(const uint8_t *keys, size_t n_keys, uint8_t *out,
                          size_t *n_out);
/* In-place sort and dedup of n 32-byte records; returns the new count. */
size_t bip138_secrets_sort(uint8_t *secrets, size_t n);
int bip138_secret_is_zero(const uint8_t secret[32]);

int bip138_path_cmp(const bip138_path *a, const bip138_path *b);
size_t bip138_paths_size(const bip138_path *paths, size_t n_paths);

void bip138_wipe(void *buf, size_t len);

#endif /* BIP138_INTERNAL_H */
