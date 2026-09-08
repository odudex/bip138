/*
 * BIP138: Compact Encryption Scheme for Non-seed Wallet Data (version 1).
 *
 * The library never allocates: every function writes into caller-provided
 * buffers and returns BIP138_ERR_SIZE when they are too small. Container and
 * item views point into the caller's buffers. Cryptography is supplied by the
 * caller through a bip138_crypto struct, so the library has no dependencies.
 */

#ifndef BIP138_H
#define BIP138_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIP138_MAGIC "BIP138"
#define BIP138_MAGIC_LEN 6
#define BIP138_VERSION 0x01
#define BIP138_ENCRYPTION_CHACHA20_POLY1305 0x01

#define BIP138_KEY_LEN 32 /* x-only public key */
#define BIP138_SECRET_LEN 32
#define BIP138_NONCE_LEN 12
#define BIP138_TAG_LEN 16
#define BIP138_MAX_COUNT 255 /* paths, path depth and secrets share a u8 */

/* Recipients per encrypt call. Bounds stack use only; the decoder accepts any
 * container the format allows. */
#ifndef BIP138_MAX_KEYS
#define BIP138_MAX_KEYS 20
#endif

#define BIP138_OK 0
#define BIP138_ERR_ARG -1     /* NULL or out-of-range argument */
#define BIP138_ERR_SIZE -2    /* output buffer too small */
#define BIP138_ERR_FORMAT -3  /* malformed container, payload or base64 */
#define BIP138_ERR_VERSION -4 /* unsupported VERSION or ENCRYPTION byte */
#define BIP138_ERR_NO_KEY -5  /* no candidate key opened the payload */
#define BIP138_ERR_CRYPTO -6  /* a crypto callback failed */
#define BIP138_ERR_LIMIT                                                       \
  -7 /* a count, depth or length exceeds the format's limit */

/*
 * Caller-supplied primitives. Each returns 0 on success, nonzero on failure.
 * aead_encrypt writes exactly pt_len + BIP138_TAG_LEN bytes to ct. aead_decrypt
 * writes exactly ct_len - BIP138_TAG_LEN bytes to pt and returns nonzero when
 * the tag does not verify. No associated data is used and buffers never
 * overlap. random may be NULL when only parse, decrypt or a fully specified
 * bip138_encrypt_ex are used.
 */
typedef struct bip138_crypto {
  void *ctx;
  int (*sha256)(void *ctx, const uint8_t *data, size_t len, uint8_t out[32]);
  int (*aead_encrypt)(void *ctx, const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *pt, size_t pt_len, uint8_t *ct);
  int (*aead_decrypt)(void *ctx, const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *ct, size_t ct_len, uint8_t *pt);
  int (*random)(void *ctx, uint8_t *buf, size_t len);
} bip138_crypto;

/* BIP32 child numbers with the hardened bit set where applicable. */
typedef struct bip138_path {
  const uint32_t *child;
  uint8_t depth; /* 1..255 */
} bip138_path;

/* Content types. Unknown TYPE values below 0x80 are reported as-is. */
#define BIP138_CONTENT_BIP 0x01
#define BIP138_CONTENT_PROPRIETARY 0x02
#define BIP138_CONTENT_STRING 0x03
#define BIP138_BIP_DESCRIPTOR 380
#define BIP138_BIP_LABELS 329
#define BIP138_BIP_WALLET_POLICY 388

typedef struct bip138_content {
  uint8_t type;
  uint16_t bip;       /* BIP138_CONTENT_BIP */
  const uint8_t *tag; /* BIP138_CONTENT_PROPRIETARY and unknown types */
  size_t tag_len;
} bip138_content;

typedef struct bip138_item {
  bip138_content content;
  const uint8_t *data;
  size_t data_len; /* at least 1 */
} bip138_item;

typedef struct bip138_item_iter {
  const uint8_t *buf;
  size_t len;
  size_t pos;
} bip138_item_iter;

/* Parsed container; every pointer references the parsed buffer. */
typedef struct bip138_container {
  const uint8_t *paths; /* path_count entries of CHILD_COUNT + children */
  size_t paths_len;
  uint8_t path_count;
  const uint8_t *secrets; /* secret_count * BIP138_SECRET_LEN bytes */
  uint8_t secret_count;
  const uint8_t *nonce;
  const uint8_t *ciphertext; /* includes the tag */
  size_t ciphertext_len;
} bip138_container;

/* --- Plaintext payload --- */

/* Bytes needed to encode the items, plus geometric zero padding when
 * geometric_pad is nonzero. Returns 0 when the items are invalid or the size
 * cannot be represented. String content must be valid UTF-8. */
size_t bip138_plaintext_size(const bip138_item *items, size_t n_items,
                             int geometric_pad);
int bip138_plaintext_encode(const bip138_item *items, size_t n_items,
                            int geometric_pad, uint8_t *out, size_t out_cap,
                            size_t *out_len);
/* Smallest geometric padding bucket holding len bytes. */
size_t bip138_padding_bucket(size_t len);

void bip138_item_iter_init(bip138_item_iter *it, const uint8_t *plaintext,
                           size_t len);
/* Returns 1 with an item, 0 at the end of the items, or a negative error.
 * Items with an unknown TYPE below 0x80 are skipped. Invalid UTF-8 in string
 * content returns BIP138_ERR_FORMAT. */
int bip138_item_next(bip138_item_iter *it, bip138_item *item);
/* Parses one CONTENT_TYPE field; *consumed receives its length. */
int bip138_content_parse(const uint8_t *buf, size_t len, bip138_content *out,
                         size_t *consumed);
size_t bip138_content_size(const bip138_content *content);
int bip138_content_encode(const bip138_content *content, uint8_t *out,
                          size_t out_cap, size_t *out_len);

/* --- Secrets --- */

int bip138_individual_secret(const bip138_crypto *c, const uint8_t key[32],
                             uint8_t out[32]);
/* Sorts, deduplicates and drops the BIP341 NUMS key. n_keys is at most
 * BIP138_MAX_KEYS; at least one key must remain. */
int bip138_decryption_secret(const bip138_crypto *c, const uint8_t *keys,
                             size_t n_keys, uint8_t out[32]);
/* INDIVIDUAL_SECRETS field: COUNT followed by the sorted, deduplicated
 * secrets. n_secrets is 1..255. */
int bip138_secrets_encode(const uint8_t *secrets, size_t n_secrets,
                          uint8_t *out, size_t out_cap, size_t *out_len);
/* Decoy bucket for n_real recipients: 5, 10, 20, 40, 80, 160 or 255. Returns 0
 * when n_real is 0 or above 255. */
size_t bip138_secret_bucket(size_t n_real);

/* --- Derivation paths --- */

/* DERIVATION_PATHS field: COUNT followed by the sorted, deduplicated paths.
 * n_paths is at most 255. Common paths are kept; bip138_encrypt drops them. */
int bip138_paths_encode(const bip138_path *paths, size_t n_paths, uint8_t *out,
                        size_t out_cap, size_t *out_len);
int bip138_path_is_common(const bip138_path *path);
/* The 140 paths every decoder tries, so encoders omit them. */
size_t bip138_common_path_count(void);
int bip138_common_path(size_t index, uint32_t child[4], size_t *depth);

/* --- Container --- */

/* Upper bound on the container size for n_secrets stored secrets (real plus
 * decoys), the given paths and a plaintext of plaintext_len bytes. Pass
 * bip138_secret_bucket(n_keys) as n_secrets for bip138_encrypt. Returns 0 for
 * invalid arguments or an unrepresentable size. */
size_t bip138_encrypt_size(size_t n_secrets, const bip138_path *paths,
                           size_t n_paths, size_t plaintext_len);
/* Encrypts an encoded plaintext to keys. nonce may be NULL to draw one at
 * random; decoys may be NULL to draw n_decoys random ones. The stored secrets
 * are the recipients' secrets plus the decoys, sorted and deduplicated. */
int bip138_encrypt_ex(const bip138_crypto *c, const uint8_t *keys,
                      size_t n_keys, const bip138_path *paths, size_t n_paths,
                      const uint8_t *nonce, const uint8_t *decoys,
                      size_t n_decoys, const uint8_t *plaintext,
                      size_t plaintext_len, uint8_t *out, size_t out_cap,
                      size_t *out_len);
/* bip138_encrypt_ex with a random nonce and random decoys up to the bucket. */
int bip138_encrypt(const bip138_crypto *c, const uint8_t *keys, size_t n_keys,
                   const bip138_path *paths, size_t n_paths,
                   const uint8_t *plaintext, size_t plaintext_len, uint8_t *out,
                   size_t out_cap, size_t *out_len);

/* Keep common derivation paths in the container instead of dropping them.
 * Costs a few bytes; lets a decoder that tries hints first open the backup
 * without walking the common set. */
#define BIP138_FLAG_KEEP_COMMON_PATHS 0x01
int bip138_encrypt_flags(const bip138_crypto *c, const uint8_t *keys,
                         size_t n_keys, const bip138_path *paths,
                         size_t n_paths, uint32_t flags,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

int bip138_is_container(const uint8_t *buf, size_t len);
/* Validates the framing; bytes after the payload are ignored. */
int bip138_parse(const uint8_t *buf, size_t len, bip138_container *out);
/* Copies path index into child (child_cap entries) and sets *depth. */
int bip138_path_at(const bip138_container *c, size_t index, uint32_t *child,
                   size_t child_cap, size_t *depth);
/* Bytes needed for the decrypted plaintext. */
size_t bip138_plaintext_max(const bip138_container *c);
/* Tries every key against every stored secret. On success the plaintext holds
 * at least one valid item (possibly an unknown type) and *key_index (optional)
 * names the key used. */
int bip138_decrypt(const bip138_crypto *c, const bip138_container *cont,
                   const uint8_t *keys, size_t n_keys, uint8_t *plaintext,
                   size_t plaintext_cap, size_t *plaintext_len,
                   size_t *key_index);

/* AEAD layer: rejects an all-zero nonce and an empty plaintext. ct holds
 * pt_len + BIP138_TAG_LEN bytes; pt holds ct_len - BIP138_TAG_LEN bytes. */
int bip138_payload_encrypt(const bip138_crypto *c, const uint8_t secret[32],
                           const uint8_t nonce[12], const uint8_t *pt,
                           size_t pt_len, uint8_t *ct, size_t ct_cap);
int bip138_payload_decrypt(const bip138_crypto *c, const uint8_t secret[32],
                           const uint8_t nonce[12], const uint8_t *ct,
                           size_t ct_len, uint8_t *pt, size_t pt_cap);

/* --- Text form (RFC 4648 base64, NUL-terminated output) --- */

/* Returns 0 on overflow. The argument must have no side effects. */
#define BIP138_BASE64_LEN(n)                                                   \
  ((n) > ((SIZE_MAX - 1) / 4) * 3 ? 0 : ((((n) + 2) / 3) * 4 + 1))
#define BIP138_BASE64_DECODED_MAX(n) (((n) / 4 + 1) * 3)

int bip138_base64_encode(const uint8_t *in, size_t len, char *out,
                         size_t out_cap, size_t *out_len);
/* ASCII whitespace is skipped; any other invalid character is an error. */
int bip138_base64_decode(const char *in, size_t len, uint8_t *out,
                         size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* BIP138_H */
