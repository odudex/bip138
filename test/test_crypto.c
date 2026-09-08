#include "test_crypto.h"
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sha256_cb(void *ctx, const uint8_t *data, size_t len,
                     uint8_t out[32]) {
  (void)ctx;
  size_t out_len = 0;
  if (psa_crypto_init() != PSA_SUCCESS)
    return -1;
  return psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &out_len) ==
                     PSA_SUCCESS &&
                 out_len == 32
             ? 0
             : -1;
}

static int import_key(const uint8_t key[32], psa_key_usage_t usage,
                      mbedtls_svc_key_id_t *id) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
  psa_set_key_bits(&attrs, 256);
  psa_set_key_usage_flags(&attrs, usage);
  psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);
  psa_status_t status = psa_import_key(&attrs, key, 32, id);
  psa_reset_key_attributes(&attrs);
  return status == PSA_SUCCESS ? 0 : -1;
}

static int aead_encrypt_cb(void *ctx, const uint8_t key[32],
                           const uint8_t nonce[12], const uint8_t *pt,
                           size_t pt_len, uint8_t *ct) {
  (void)ctx;
  mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
  size_t out_len = 0;
  if (psa_crypto_init() != PSA_SUCCESS ||
      import_key(key, PSA_KEY_USAGE_ENCRYPT, &id))
    return -1;
  psa_status_t status = psa_aead_encrypt(id, PSA_ALG_CHACHA20_POLY1305, nonce,
                                         BIP138_NONCE_LEN, NULL, 0, pt, pt_len,
                                         ct, pt_len + BIP138_TAG_LEN, &out_len);
  psa_destroy_key(id);
  return status == PSA_SUCCESS && out_len == pt_len + BIP138_TAG_LEN ? 0 : -1;
}

static int aead_decrypt_cb(void *ctx, const uint8_t key[32],
                           const uint8_t nonce[12], const uint8_t *ct,
                           size_t ct_len, uint8_t *pt) {
  (void)ctx;
  mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
  size_t out_len = 0;
  if (ct_len < BIP138_TAG_LEN)
    return -1;
  if (psa_crypto_init() != PSA_SUCCESS ||
      import_key(key, PSA_KEY_USAGE_DECRYPT, &id))
    return -1;
  psa_status_t status = psa_aead_decrypt(id, PSA_ALG_CHACHA20_POLY1305, nonce,
                                         BIP138_NONCE_LEN, NULL, 0, ct, ct_len,
                                         pt, ct_len - BIP138_TAG_LEN, &out_len);
  psa_destroy_key(id);
  return status == PSA_SUCCESS && out_len == ct_len - BIP138_TAG_LEN ? 0 : -1;
}

static int random_cb(void *ctx, uint8_t *buf, size_t len) {
  (void)ctx;
  if (psa_crypto_init() != PSA_SUCCESS)
    return -1;
  return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
}

static uint32_t seeded_state;

static int seeded_random_cb(void *ctx, uint8_t *buf, size_t len) {
  (void)ctx;
  for (size_t i = 0; i < len; i++) {
    seeded_state = seeded_state * 1664525u + 1013904223u;
    buf[i] = (uint8_t)(seeded_state >> 24);
  }
  return 0;
}

static int fail_sha256(void *ctx, const uint8_t *d, size_t l, uint8_t o[32]) {
  (void)ctx;
  (void)d;
  (void)l;
  (void)o;
  return -1;
}

static int fail_aead(void *ctx, const uint8_t k[32], const uint8_t n[12],
                     const uint8_t *in, size_t len, uint8_t *out) {
  (void)ctx;
  (void)k;
  (void)n;
  (void)in;
  (void)len;
  (void)out;
  return -1;
}

static int fail_random(void *ctx, uint8_t *buf, size_t len) {
  (void)ctx;
  (void)buf;
  (void)len;
  return -1;
}

const bip138_crypto *test_crypto(void) {
  static const bip138_crypto c = {NULL, sha256_cb, aead_encrypt_cb,
                                  aead_decrypt_cb, random_cb};
  return &c;
}

const bip138_crypto *test_crypto_failing(void) {
  static const bip138_crypto c = {NULL, fail_sha256, fail_aead, fail_aead,
                                  fail_random};
  return &c;
}

const bip138_crypto *test_crypto_seeded(uint32_t seed) {
  static const bip138_crypto c = {NULL, sha256_cb, aead_encrypt_cb,
                                  aead_decrypt_cb, seeded_random_cb};
  seeded_state = seed;
  return &c;
}
