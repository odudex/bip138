#include "bip138_internal.h"
#include <string.h>

#define HEADER_LEN (BIP138_MAGIC_LEN + 1)
#define DECOY_RETRIES 8

static int nonce_is_zero(const uint8_t nonce[BIP138_NONCE_LEN]) {
  uint8_t acc = 0;
  for (size_t i = 0; i < BIP138_NONCE_LEN; i++)
    acc |= nonce[i];
  return acc == 0;
}

int bip138_payload_encrypt(const bip138_crypto *c, const uint8_t secret[32],
                           const uint8_t nonce[12], const uint8_t *pt,
                           size_t pt_len, uint8_t *ct, size_t ct_cap) {
  if (!c || !c->aead_encrypt || !secret || !nonce || !pt || !ct)
    return BIP138_ERR_ARG;
  if (pt_len == 0 || nonce_is_zero(nonce))
    return BIP138_ERR_ARG;
  if (!bip138_plaintext_len_valid(pt_len))
    return BIP138_ERR_LIMIT;
  if (ct_cap < BIP138_TAG_LEN || pt_len > ct_cap - BIP138_TAG_LEN)
    return BIP138_ERR_SIZE;
  return c->aead_encrypt(c->ctx, secret, nonce, pt, pt_len, ct) == 0
             ? BIP138_OK
             : BIP138_ERR_CRYPTO;
}

int bip138_payload_decrypt(const bip138_crypto *c, const uint8_t secret[32],
                           const uint8_t nonce[12], const uint8_t *ct,
                           size_t ct_len, uint8_t *pt, size_t pt_cap) {
  if (!c || !c->aead_decrypt || !secret || !nonce || !ct || !pt)
    return BIP138_ERR_ARG;
  if (ct_len <= BIP138_TAG_LEN || nonce_is_zero(nonce))
    return BIP138_ERR_ARG;
  if (!bip138_plaintext_len_valid(ct_len - BIP138_TAG_LEN))
    return BIP138_ERR_LIMIT;
  if (pt_cap < ct_len - BIP138_TAG_LEN)
    return BIP138_ERR_SIZE;
  return c->aead_decrypt(c->ctx, secret, nonce, ct, ct_len, pt) == 0
             ? BIP138_OK
             : BIP138_ERR_NO_KEY;
}

size_t bip138_encrypt_size(size_t n_secrets, const bip138_path *paths,
                           size_t n_paths, size_t plaintext_len) {
  if (n_secrets == 0 || n_secrets > BIP138_MAX_COUNT || plaintext_len == 0 ||
      !bip138_plaintext_len_valid(plaintext_len) ||
      plaintext_len > SIZE_MAX - BIP138_TAG_LEN)
    return 0;
  size_t paths_len = bip138_paths_size(paths, n_paths);
  if (paths_len == 0)
    return 0;
  size_t ct_len = plaintext_len + BIP138_TAG_LEN;
  size_t prefix = HEADER_LEN + paths_len + 1 + n_secrets * BIP138_SECRET_LEN +
                  1 + BIP138_NONCE_LEN + bip138_varint_size(ct_len);
  return ct_len > SIZE_MAX - prefix ? 0 : prefix + ct_len;
}

static int draw_decoy(const bip138_crypto *c, uint8_t *secrets, size_t n,
                      uint8_t *out) {
  for (int attempt = 0; attempt < DECOY_RETRIES; attempt++) {
    if (c->random(c->ctx, out, BIP138_SECRET_LEN) != 0)
      return BIP138_ERR_CRYPTO;
    if (bip138_secret_is_zero(out))
      continue;
    size_t i = 0;
    while (i < n &&
           memcmp(secrets + i * BIP138_SECRET_LEN, out, BIP138_SECRET_LEN) != 0)
      i++;
    if (i == n)
      return BIP138_OK;
  }
  return BIP138_ERR_CRYPTO;
}

static int encode_paths(const bip138_path *paths, size_t n_paths,
                        uint32_t flags, uint8_t *out, size_t out_cap,
                        size_t *out_len) {
  bip138_path kept[BIP138_MAX_COUNT];
  size_t n = 0;
  if (n_paths > BIP138_MAX_COUNT)
    return BIP138_ERR_LIMIT;
  for (size_t i = 0; i < n_paths; i++) {
    if ((flags & BIP138_FLAG_KEEP_COMMON_PATHS) ||
        !bip138_path_is_common(&paths[i]))
      kept[n++] = paths[i];
  }
  return bip138_paths_encode(kept, n, out, out_cap, out_len);
}

static int encrypt_impl(const bip138_crypto *c, const uint8_t *keys,
                        size_t n_keys, const bip138_path *paths, size_t n_paths,
                        uint32_t flags, const uint8_t *nonce,
                        const uint8_t *decoys, size_t n_decoys,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *out, size_t out_cap, size_t *out_len) {
  uint8_t unique[BIP138_KEY_LEN * BIP138_MAX_KEYS];
  uint8_t secret[BIP138_SECRET_LEN];
  size_t n_unique = 0;
  int ret;

  if (!c || !c->sha256 || !c->aead_encrypt || !keys || !plaintext || !out ||
      !out_len || (!paths && n_paths > 0) ||
      (!decoys && n_decoys > 0 && !c->random) || (!nonce && !c->random))
    return BIP138_ERR_ARG;
  if (plaintext_len == 0)
    return BIP138_ERR_ARG;
  if (!bip138_plaintext_len_valid(plaintext_len))
    return BIP138_ERR_LIMIT;
  if (plaintext_len > SIZE_MAX - BIP138_TAG_LEN)
    return BIP138_ERR_SIZE;

  ret = bip138_keys_normalize(keys, n_keys, unique, &n_unique);
  if (ret != BIP138_OK)
    return ret;
  if (n_unique > BIP138_MAX_COUNT || n_decoys > BIP138_MAX_COUNT - n_unique)
    return BIP138_ERR_LIMIT;

  size_t pos = 0;
  size_t written = 0;
  if (out_cap < HEADER_LEN)
    return BIP138_ERR_SIZE;
  memcpy(out, BIP138_MAGIC, BIP138_MAGIC_LEN);
  out[BIP138_MAGIC_LEN] = BIP138_VERSION;
  pos = HEADER_LEN;

  ret = encode_paths(paths, n_paths, flags, out + pos, out_cap - pos, &written);
  if (ret != BIP138_OK)
    return ret;
  pos += written;

  size_t n_secrets = n_unique + n_decoys;
  if (out_cap - pos < 1 + n_secrets * BIP138_SECRET_LEN)
    return BIP138_ERR_SIZE;
  uint8_t *secrets = out + pos + 1;

  ret = bip138_tagged_hash(c, BIP138_TAG_DECRYPTION_SECRET, unique,
                           n_unique * BIP138_KEY_LEN, secret);
  for (size_t i = 0; ret == BIP138_OK && i < n_unique; i++) {
    uint8_t *ci = secrets + i * BIP138_SECRET_LEN;
    ret = bip138_tagged_hash(c, BIP138_TAG_INDIVIDUAL_SECRET,
                             unique + i * BIP138_KEY_LEN, BIP138_KEY_LEN, ci);
    for (size_t k = 0; k < BIP138_SECRET_LEN; k++)
      ci[k] ^= secret[k];
    if (bip138_secret_is_zero(ci))
      ret = BIP138_ERR_CRYPTO;
  }
  for (size_t i = 0; ret == BIP138_OK && i < n_decoys; i++) {
    uint8_t *di = secrets + (n_unique + i) * BIP138_SECRET_LEN;
    if (decoys) {
      memcpy(di, decoys + i * BIP138_SECRET_LEN, BIP138_SECRET_LEN);
      if (bip138_secret_is_zero(di))
        ret = BIP138_ERR_ARG;
    } else {
      ret = draw_decoy(c, secrets, n_unique + i, di);
    }
  }
  if (ret != BIP138_OK)
    goto cleanup;
  n_secrets = bip138_secrets_sort(secrets, n_secrets);
  out[pos] = (uint8_t)n_secrets;
  pos += 1 + n_secrets * BIP138_SECRET_LEN;

  size_t ct_len = plaintext_len + BIP138_TAG_LEN;
  size_t prefix = 1 + BIP138_NONCE_LEN + bip138_varint_size(ct_len);
  if (out_cap - pos < prefix || ct_len > out_cap - pos - prefix) {
    ret = BIP138_ERR_SIZE;
    goto cleanup;
  }
  out[pos++] = BIP138_ENCRYPTION_CHACHA20_POLY1305;
  uint8_t *nonce_out = out + pos;
  if (nonce) {
    memcpy(nonce_out, nonce, BIP138_NONCE_LEN);
  } else {
    for (int attempt = 0;; attempt++) {
      if (c->random(c->ctx, nonce_out, BIP138_NONCE_LEN) != 0) {
        ret = BIP138_ERR_CRYPTO;
        goto cleanup;
      }
      if (!nonce_is_zero(nonce_out))
        break;
      if (attempt == 1) {
        ret = BIP138_ERR_CRYPTO;
        goto cleanup;
      }
    }
  }
  pos += BIP138_NONCE_LEN;
  ret = bip138_varint_write(out + pos, out_cap - pos, ct_len, &written);
  if (ret != BIP138_OK)
    goto cleanup;
  pos += written;
  ret = bip138_payload_encrypt(c, secret, nonce_out, plaintext, plaintext_len,
                               out + pos, out_cap - pos);
  if (ret == BIP138_OK)
    *out_len = pos + ct_len;

cleanup:
  bip138_wipe(secret, sizeof(secret));
  bip138_wipe(unique, sizeof(unique));
  return ret;
}

int bip138_encrypt_ex(const bip138_crypto *c, const uint8_t *keys,
                      size_t n_keys, const bip138_path *paths, size_t n_paths,
                      const uint8_t *nonce, const uint8_t *decoys,
                      size_t n_decoys, const uint8_t *plaintext,
                      size_t plaintext_len, uint8_t *out, size_t out_cap,
                      size_t *out_len) {
  return encrypt_impl(c, keys, n_keys, paths, n_paths, 0, nonce, decoys,
                      n_decoys, plaintext, plaintext_len, out, out_cap,
                      out_len);
}

int bip138_encrypt_flags(const bip138_crypto *c, const uint8_t *keys,
                         size_t n_keys, const bip138_path *paths,
                         size_t n_paths, uint32_t flags,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *out, size_t out_cap, size_t *out_len) {
  uint8_t unique[BIP138_KEY_LEN * BIP138_MAX_KEYS];
  size_t n_unique = 0;
  if (!c || !c->random)
    return BIP138_ERR_ARG;
  int ret = bip138_keys_normalize(keys, n_keys, unique, &n_unique);
  bip138_wipe(unique, sizeof(unique));
  if (ret != BIP138_OK)
    return ret;
  size_t bucket = bip138_secret_bucket(n_unique);
  return encrypt_impl(c, keys, n_keys, paths, n_paths, flags, NULL, NULL,
                      bucket - n_unique, plaintext, plaintext_len, out, out_cap,
                      out_len);
}

int bip138_encrypt(const bip138_crypto *c, const uint8_t *keys, size_t n_keys,
                   const bip138_path *paths, size_t n_paths,
                   const uint8_t *plaintext, size_t plaintext_len, uint8_t *out,
                   size_t out_cap, size_t *out_len) {
  return bip138_encrypt_flags(c, keys, n_keys, paths, n_paths, 0, plaintext,
                              plaintext_len, out, out_cap, out_len);
}

int bip138_is_container(const uint8_t *buf, size_t len) {
  return buf && len >= HEADER_LEN &&
         memcmp(buf, BIP138_MAGIC, BIP138_MAGIC_LEN) == 0 &&
         buf[BIP138_MAGIC_LEN] == BIP138_VERSION;
}

int bip138_parse(const uint8_t *buf, size_t len, bip138_container *out) {
  if (!buf || !out)
    return BIP138_ERR_ARG;
  if (len < HEADER_LEN || memcmp(buf, BIP138_MAGIC, BIP138_MAGIC_LEN) != 0)
    return BIP138_ERR_FORMAT;
  if (buf[BIP138_MAGIC_LEN] != BIP138_VERSION)
    return BIP138_ERR_VERSION;
  memset(out, 0, sizeof(*out));
  size_t pos = HEADER_LEN;

  if (len - pos < 1)
    return BIP138_ERR_FORMAT;
  out->path_count = buf[pos++];
  out->paths = buf + pos;
  for (size_t i = 0; i < out->path_count; i++) {
    if (len - pos < 1 || buf[pos] == 0)
      return BIP138_ERR_FORMAT;
    size_t path_len = 1 + 4 * (size_t)buf[pos];
    if (len - pos < path_len)
      return BIP138_ERR_FORMAT;
    pos += path_len;
  }
  out->paths_len = (size_t)(buf + pos - out->paths);

  if (len - pos < 1 || buf[pos] == 0)
    return BIP138_ERR_FORMAT;
  out->secret_count = buf[pos++];
  if (len - pos < (size_t)out->secret_count * BIP138_SECRET_LEN)
    return BIP138_ERR_FORMAT;
  out->secrets = buf + pos;
  pos += (size_t)out->secret_count * BIP138_SECRET_LEN;

  if (len - pos < 1 + BIP138_NONCE_LEN)
    return BIP138_ERR_FORMAT;
  if (buf[pos] != BIP138_ENCRYPTION_CHACHA20_POLY1305)
    return BIP138_ERR_VERSION;
  pos++;
  out->nonce = buf + pos;
  if (nonce_is_zero(out->nonce))
    return BIP138_ERR_FORMAT;
  pos += BIP138_NONCE_LEN;

  uint64_t ct_len = 0;
  size_t consumed = 0;
  if (bip138_varint_read(buf + pos, len - pos, &ct_len, &consumed) != BIP138_OK)
    return BIP138_ERR_FORMAT;
  pos += consumed;
  /* The ciphertext length is opaque framing: it only has to fit the remaining
   * bytes. A ciphertext too short to hold the AEAD tag, or one beyond the
   * cipher's plaintext limit, is reported by bip138_decrypt, keeping the parser
   * agnostic to the encryption algorithm. */
  if (ct_len > len - pos)
    return BIP138_ERR_FORMAT;
  out->ciphertext = buf + pos;
  out->ciphertext_len = (size_t)ct_len;
  return BIP138_OK;
}

int bip138_path_at(const bip138_container *c, size_t index, uint32_t *child,
                   size_t child_cap, size_t *depth) {
  if (!c || !child || !depth)
    return BIP138_ERR_ARG;
  if (index >= c->path_count)
    return BIP138_ERR_ARG;
  const uint8_t *p = c->paths;
  for (size_t i = 0; i < index; i++)
    p += 1 + 4 * (size_t)p[0];
  size_t n = p[0];
  if (child_cap < n)
    return BIP138_ERR_SIZE;
  for (size_t i = 0; i < n; i++) {
    const uint8_t *b = p + 1 + 4 * i;
    child[i] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
               ((uint32_t)b[2] << 8) | b[3];
  }
  *depth = n;
  return BIP138_OK;
}

size_t bip138_plaintext_max(const bip138_container *c) {
  return c && c->ciphertext_len > BIP138_TAG_LEN &&
                 bip138_plaintext_len_valid(c->ciphertext_len - BIP138_TAG_LEN)
             ? c->ciphertext_len - BIP138_TAG_LEN
             : 0;
}

static int plaintext_is_valid(const uint8_t *pt, size_t len) {
  bip138_item_iter it;
  bip138_item item;
  bip138_item_iter_init(&it, pt, len);
  int ret;
  while ((ret = bip138_item_next(&it, &item)) == 1)
    ;
  /* The iterator advances over unknown items too. A padding-only payload
   * leaves pos at zero; unknown-only payloads are structurally valid. */
  return ret == 0 && it.pos > 0;
}

int bip138_decrypt(const bip138_crypto *c, const bip138_container *cont,
                   const uint8_t *keys, size_t n_keys, uint8_t *plaintext,
                   size_t plaintext_cap, size_t *plaintext_len,
                   size_t *key_index) {
  uint8_t si[BIP138_SECRET_LEN];
  uint8_t secret[BIP138_SECRET_LEN];
  int ret = BIP138_ERR_NO_KEY;

  if (!c || !c->sha256 || !c->aead_decrypt || !cont || !keys || n_keys == 0 ||
      !plaintext || !plaintext_len)
    return BIP138_ERR_ARG;
  if (cont->ciphertext_len <= BIP138_TAG_LEN)
    return BIP138_ERR_FORMAT;
  if (!bip138_plaintext_len_valid(cont->ciphertext_len - BIP138_TAG_LEN))
    return BIP138_ERR_LIMIT;
  size_t pt_len = cont->ciphertext_len - BIP138_TAG_LEN;
  if (plaintext_cap < pt_len)
    return BIP138_ERR_SIZE;

  for (size_t k = 0; k < n_keys && ret == BIP138_ERR_NO_KEY; k++) {
    ret = bip138_individual_secret(c, keys + k * BIP138_KEY_LEN, si);
    if (ret != BIP138_OK)
      break;
    ret = BIP138_ERR_NO_KEY;
    for (size_t j = 0; j < cont->secret_count; j++) {
      const uint8_t *cj = cont->secrets + j * BIP138_SECRET_LEN;
      size_t dup = 0;
      while (dup < j && memcmp(cont->secrets + dup * BIP138_SECRET_LEN, cj,
                               BIP138_SECRET_LEN) != 0)
        dup++;
      if (dup < j)
        continue;
      for (size_t b = 0; b < BIP138_SECRET_LEN; b++)
        secret[b] = cj[b] ^ si[b];
      if (c->aead_decrypt(c->ctx, secret, cont->nonce, cont->ciphertext,
                          cont->ciphertext_len, plaintext) != 0)
        continue;
      if (!plaintext_is_valid(plaintext, pt_len)) {
        ret = BIP138_ERR_FORMAT;
        break;
      }
      *plaintext_len = pt_len;
      if (key_index)
        *key_index = k;
      ret = BIP138_OK;
      break;
    }
  }
  if (ret != BIP138_OK)
    bip138_wipe(plaintext, pt_len);
  bip138_wipe(si, sizeof(si));
  bip138_wipe(secret, sizeof(secret));
  return ret;
}
