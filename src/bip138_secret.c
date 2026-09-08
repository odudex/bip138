#include "bip138_internal.h"
#include <string.h>

const uint8_t bip138_nums_key[BIP138_KEY_LEN] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b,
    0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec,
    0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};

void bip138_wipe(void *buf, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)buf;
  while (len--)
    *p++ = 0;
}

int bip138_secret_is_zero(const uint8_t secret[32]) {
  uint8_t acc = 0;
  for (size_t i = 0; i < BIP138_SECRET_LEN; i++)
    acc |= secret[i];
  return acc == 0;
}

int bip138_tagged_hash(const bip138_crypto *c, const char *tag,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
  uint8_t buf[64 + BIP138_KEY_LEN * BIP138_MAX_KEYS];
  if (msg_len > sizeof(buf) - 64)
    return BIP138_ERR_LIMIT;
  if (c->sha256(c->ctx, (const uint8_t *)tag, strlen(tag), buf) != 0)
    return BIP138_ERR_CRYPTO;
  memcpy(buf + 32, buf, 32);
  memcpy(buf + 64, msg, msg_len);
  int ret = c->sha256(c->ctx, buf, 64 + msg_len, out) == 0 ? BIP138_OK
                                                           : BIP138_ERR_CRYPTO;
  bip138_wipe(buf, sizeof(buf));
  return ret;
}

size_t bip138_secrets_sort(uint8_t *secrets, size_t n) {
  uint8_t tmp[BIP138_SECRET_LEN];
  for (size_t i = 1; i < n; i++) {
    memcpy(tmp, secrets + i * BIP138_SECRET_LEN, BIP138_SECRET_LEN);
    size_t j = i;
    while (j > 0 && memcmp(secrets + (j - 1) * BIP138_SECRET_LEN, tmp,
                           BIP138_SECRET_LEN) > 0) {
      memcpy(secrets + j * BIP138_SECRET_LEN,
             secrets + (j - 1) * BIP138_SECRET_LEN, BIP138_SECRET_LEN);
      j--;
    }
    memcpy(secrets + j * BIP138_SECRET_LEN, tmp, BIP138_SECRET_LEN);
  }
  size_t out = n > 0 ? 1 : 0;
  for (size_t i = 1; i < n; i++) {
    if (memcmp(secrets + (out - 1) * BIP138_SECRET_LEN,
               secrets + i * BIP138_SECRET_LEN, BIP138_SECRET_LEN) != 0) {
      if (out != i)
        memcpy(secrets + out * BIP138_SECRET_LEN,
               secrets + i * BIP138_SECRET_LEN, BIP138_SECRET_LEN);
      out++;
    }
  }
  return out;
}

int bip138_keys_normalize(const uint8_t *keys, size_t n_keys, uint8_t *out,
                          size_t *n_out) {
  if (!keys || !out || !n_out || n_keys == 0)
    return BIP138_ERR_ARG;
  if (n_keys > BIP138_MAX_KEYS)
    return BIP138_ERR_LIMIT;
  size_t n = 0;
  for (size_t i = 0; i < n_keys; i++) {
    if (memcmp(keys + i * BIP138_KEY_LEN, bip138_nums_key, BIP138_KEY_LEN) == 0)
      continue;
    memcpy(out + n * BIP138_KEY_LEN, keys + i * BIP138_KEY_LEN, BIP138_KEY_LEN);
    n++;
  }
  n = bip138_secrets_sort(out, n);
  if (n == 0)
    return BIP138_ERR_ARG;
  *n_out = n;
  return BIP138_OK;
}

int bip138_individual_secret(const bip138_crypto *c, const uint8_t key[32],
                             uint8_t out[32]) {
  if (!c || !c->sha256 || !key || !out)
    return BIP138_ERR_ARG;
  return bip138_tagged_hash(c, BIP138_TAG_INDIVIDUAL_SECRET, key,
                            BIP138_KEY_LEN, out);
}

int bip138_decryption_secret(const bip138_crypto *c, const uint8_t *keys,
                             size_t n_keys, uint8_t out[32]) {
  uint8_t sorted[BIP138_KEY_LEN * BIP138_MAX_KEYS];
  size_t n = 0;
  if (!c || !c->sha256 || !out)
    return BIP138_ERR_ARG;
  int ret = bip138_keys_normalize(keys, n_keys, sorted, &n);
  if (ret == BIP138_OK)
    ret = bip138_tagged_hash(c, BIP138_TAG_DECRYPTION_SECRET, sorted,
                             n * BIP138_KEY_LEN, out);
  return ret;
}

int bip138_secrets_encode(const uint8_t *secrets, size_t n_secrets,
                          uint8_t *out, size_t out_cap, size_t *out_len) {
  if (!secrets || !out || !out_len)
    return BIP138_ERR_ARG;
  if (n_secrets == 0 || n_secrets > BIP138_MAX_COUNT)
    return BIP138_ERR_LIMIT;
  if (out_cap < 1 + n_secrets * BIP138_SECRET_LEN)
    return BIP138_ERR_SIZE;
  memcpy(out + 1, secrets, n_secrets * BIP138_SECRET_LEN);
  size_t n = bip138_secrets_sort(out + 1, n_secrets);
  out[0] = (uint8_t)n;
  *out_len = 1 + n * BIP138_SECRET_LEN;
  return BIP138_OK;
}

size_t bip138_secret_bucket(size_t n_real) {
  if (n_real == 0 || n_real > BIP138_MAX_COUNT)
    return 0;
  size_t bucket = 5;
  while (bucket < n_real)
    bucket *= 2;
  return bucket > BIP138_MAX_COUNT ? BIP138_MAX_COUNT : bucket;
}
