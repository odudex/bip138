#include "bip138.h"
#include "test_crypto.h"
#include "vectors.h"
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(desc, cond)                                                      \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      printf("FAIL %s:%d %s: %s\n", __FILE__, __LINE__, desc, #cond);          \
    }                                                                          \
  } while (0)

static void paths_from_tv(const tv_paths *tv, bip138_path *out) {
  size_t offset = 0;
  for (size_t i = 0; i < tv->n; i++) {
    out[i].child = tv->children + offset;
    out[i].depth = (uint8_t)tv->depths[i];
    offset += tv->depths[i];
  }
}

static int tv_paths_representable(const tv_paths *tv) {
  for (size_t i = 0; i < tv->n; i++) {
    if (tv->depths[i] > BIP138_MAX_COUNT)
      return 0;
  }
  return tv->n <= BIP138_MAX_COUNT;
}

static void test_encryption_secret(void) {
  const bip138_crypto *c = test_crypto();
  for (size_t v = 0; v < TV_ENCRYPTION_SECRET_COUNT; v++) {
    const tv_encryption_secret *tv = &tv_encryption_secret_vectors[v];
    size_t n_keys = tv->keys.n / BIP138_KEY_LEN;
    uint8_t secret[32];
    CHECK(tv->desc,
          bip138_decryption_secret(c, tv->keys.p, n_keys, secret) == BIP138_OK);
    CHECK(tv->desc, memcmp(secret, tv->secret.p, 32) == 0);
    size_t n_ind = tv->individual.n / BIP138_SECRET_LEN;
    for (size_t k = 0; k < n_keys; k++) {
      uint8_t si[32];
      CHECK(tv->desc, bip138_individual_secret(
                          c, tv->keys.p + k * BIP138_KEY_LEN, si) == BIP138_OK);
      for (size_t b = 0; b < 32; b++)
        si[b] ^= secret[b];
      int found = 0;
      for (size_t j = 0; j < n_ind; j++)
        found |= memcmp(si, tv->individual.p + j * 32, 32) == 0;
      CHECK(tv->desc, found);
    }
  }
}

static void test_individual_secrets(void) {
  uint8_t out[1 + 255 * BIP138_SECRET_LEN];
  for (size_t v = 0; v < TV_INDIVIDUAL_SECRETS_COUNT; v++) {
    const tv_individual_secrets *tv = &tv_individual_secrets_vectors[v];
    size_t len = 0;
    int ret = bip138_secrets_encode(tv->secrets.p, tv->secrets.n / 32, out,
                                    sizeof(out), &len);
    if (tv->expected.p) {
      CHECK(tv->desc, ret == BIP138_OK);
      CHECK(tv->desc, len == tv->expected.n);
      CHECK(tv->desc,
            len == tv->expected.n && memcmp(out, tv->expected.p, len) == 0);
    } else {
      CHECK(tv->desc, ret != BIP138_OK);
    }
  }
}

static void test_derivation_paths(void) {
  static bip138_path paths[256];
  static uint8_t out[1 + 256 * (1 + 4 * 256)];
  for (size_t v = 0; v < TV_DERIVATION_PATH_COUNT; v++) {
    const tv_derivation_path *tv = &tv_derivation_path_vectors[v];
    if (!tv_paths_representable(&tv->paths)) {
      CHECK(tv->desc, tv->expected.p == NULL);
      continue;
    }
    paths_from_tv(&tv->paths, paths);
    size_t len = 0;
    int ret = bip138_paths_encode(paths, tv->paths.n, out, sizeof(out), &len);
    if (tv->expected.p) {
      CHECK(tv->desc, ret == BIP138_OK);
      CHECK(tv->desc,
            len == tv->expected.n && memcmp(out, tv->expected.p, len) == 0);
    } else {
      CHECK(tv->desc, ret != BIP138_OK);
    }
  }
}

static void test_content_type(void) {
  for (size_t v = 0; v < TV_CONTENT_TYPE_COUNT; v++) {
    const tv_content_type *tv = &tv_content_type_vectors[v];
    bip138_content content;
    size_t consumed = 0;
    int ret =
        bip138_content_parse(tv->content.p, tv->content.n, &content, &consumed);
    if (tv->valid) {
      uint8_t out[64];
      size_t len = 0;
      CHECK(tv->desc, ret == BIP138_OK && consumed == tv->content.n);
      CHECK(tv->desc, bip138_content_encode(&content, out, sizeof(out), &len) ==
                          BIP138_OK);
      CHECK(tv->desc,
            len == tv->content.n && memcmp(out, tv->content.p, len) == 0);
    } else {
      CHECK(tv->desc, ret != BIP138_OK);
    }
  }
}

static void test_chacha(void) {
  const bip138_crypto *c = test_crypto();
  for (size_t v = 0; v < TV_CHACHA_COUNT; v++) {
    const tv_chacha *tv = &tv_chacha_vectors[v];
    uint8_t ct[256];
    uint8_t pt[256];
    int ret =
        bip138_payload_encrypt(c, tv->secret.p, tv->nonce.p, tv->plaintext.p,
                               tv->plaintext.n, ct, sizeof(ct));
    if (!tv->ciphertext.p) {
      CHECK(tv->desc, ret != BIP138_OK);
      continue;
    }
    CHECK(tv->desc, ret == BIP138_OK);
    CHECK(tv->desc, tv->ciphertext.n == tv->plaintext.n + BIP138_TAG_LEN &&
                        memcmp(ct, tv->ciphertext.p, tv->ciphertext.n) == 0);
    CHECK(tv->desc, bip138_payload_decrypt(c, tv->secret.p, tv->nonce.p,
                                           tv->ciphertext.p, tv->ciphertext.n,
                                           pt, sizeof(pt)) == BIP138_OK);
    CHECK(tv->desc, memcmp(pt, tv->plaintext.p, tv->plaintext.n) == 0);
    ct[0] ^= 0x01;
    CHECK(tv->desc, bip138_payload_decrypt(c, tv->secret.p, tv->nonce.p, ct,
                                           tv->ciphertext.n, pt,
                                           sizeof(pt)) == BIP138_ERR_NO_KEY);
  }
}

static void check_backup_decrypt(const tv_backup *tv, const uint8_t *blob,
                                 size_t blob_len, const uint8_t *plaintext,
                                 size_t plaintext_len) {
  const bip138_crypto *c = test_crypto();
  bip138_container cont;
  uint8_t pt[4096];
  size_t pt_len = 0;
  size_t key_index = 99;
  size_t n_keys = tv->keys.n / BIP138_KEY_LEN;

  CHECK(tv->desc, bip138_parse(blob, blob_len, &cont) == BIP138_OK);
  CHECK(tv->desc, bip138_plaintext_max(&cont) == plaintext_len);
  for (size_t k = 0; k < n_keys; k++) {
    CHECK(tv->desc,
          bip138_decrypt(c, &cont, tv->keys.p + k * BIP138_KEY_LEN, 1, pt,
                         sizeof(pt), &pt_len, &key_index) == BIP138_OK);
    CHECK(tv->desc, key_index == 0 && pt_len == plaintext_len &&
                        memcmp(pt, plaintext, plaintext_len) == 0);
  }
  uint8_t foreign[BIP138_KEY_LEN];
  memset(foreign, 0x42, sizeof(foreign));
  CHECK(tv->desc, bip138_decrypt(c, &cont, foreign, 1, pt, sizeof(pt), &pt_len,
                                 NULL) == BIP138_ERR_NO_KEY);

  bip138_item_iter it;
  bip138_item item;
  bip138_item_iter_init(&it, pt, 0);
  bip138_decrypt(c, &cont, tv->keys.p, n_keys, pt, sizeof(pt), &pt_len, NULL);
  bip138_item_iter_init(&it, pt, pt_len);
  for (size_t i = 0; i < tv->n_items; i++) {
    uint8_t content[64];
    size_t content_len = 0;
    CHECK(tv->desc, bip138_item_next(&it, &item) == 1);
    CHECK(tv->desc,
          bip138_content_encode(&item.content, content, sizeof(content),
                                &content_len) == BIP138_OK);
    CHECK(tv->desc,
          content_len == tv->items[i].content.n &&
              memcmp(content, tv->items[i].content.p, content_len) == 0);
    CHECK(tv->desc,
          item.data_len == tv->items[i].plaintext.n &&
              memcmp(item.data, tv->items[i].plaintext.p, item.data_len) == 0);
  }
  CHECK(tv->desc, bip138_item_next(&it, &item) == 0);
}

static void test_encrypted_backup(void) {
  const bip138_crypto *c = test_crypto();
  static uint8_t plaintext[4096];
  static uint8_t out[8192];
  static uint8_t with_trailing[8192];
  static char b64[16384];
  bip138_path paths[16];
  bip138_item items[TV_BACKUP_MAX_ITEMS];

  for (size_t v = 0; v < TV_BACKUP_COUNT; v++) {
    const tv_backup *tv = &tv_backup_vectors[v];
    size_t n_keys = tv->keys.n / BIP138_KEY_LEN;
    size_t n_decoys = tv->decoys.n / BIP138_SECRET_LEN;
    size_t plaintext_len = 0;
    size_t out_len = 0;
    size_t consumed = 0;

    for (size_t i = 0; i < tv->n_items; i++) {
      CHECK(tv->desc,
            bip138_content_parse(tv->items[i].content.p, tv->items[i].content.n,
                                 &items[i].content, &consumed) == BIP138_OK);
      items[i].data = tv->items[i].plaintext.p;
      items[i].data_len = tv->items[i].plaintext.n;
    }
    CHECK(tv->desc, bip138_plaintext_encode(items, tv->n_items, 0, plaintext,
                                            sizeof(plaintext),
                                            &plaintext_len) == BIP138_OK);
    paths_from_tv(&tv->paths, paths);
    CHECK(tv->desc, bip138_encrypt_size(n_keys + n_decoys, paths, tv->paths.n,
                                        plaintext_len) <= sizeof(out));
    int ret = bip138_encrypt_ex(c, tv->keys.p, n_keys, paths, tv->paths.n,
                                tv->nonce.p, tv->decoys.p, n_decoys, plaintext,
                                plaintext_len, out, sizeof(out), &out_len);
    if (!tv->valid) {
      bip138_container cont;
      CHECK(tv->desc, ret != BIP138_OK);
      CHECK(tv->desc,
            bip138_parse(tv->expected.p, tv->expected.n, &cont) != BIP138_OK);
      continue;
    }
    CHECK(tv->desc, ret == BIP138_OK);
    CHECK(tv->desc, out_len == tv->expected.n &&
                        memcmp(out, tv->expected.p, out_len) == 0);
    CHECK(tv->desc, out_len <= bip138_encrypt_size(n_keys + n_decoys, paths,
                                                   tv->paths.n, plaintext_len));

    size_t b64_len = 0;
    CHECK(tv->desc, bip138_base64_encode(out, out_len, b64, sizeof(b64),
                                         &b64_len) == BIP138_OK);
    CHECK(tv->desc, strcmp(b64, tv->expected_base64) == 0);
    size_t decoded_len = 0;
    CHECK(tv->desc,
          bip138_base64_decode(tv->expected_base64, strlen(tv->expected_base64),
                               with_trailing, sizeof(with_trailing),
                               &decoded_len) == BIP138_OK);
    CHECK(tv->desc,
          decoded_len == out_len && memcmp(with_trailing, out, out_len) == 0);

    CHECK(tv->desc, bip138_is_container(out, out_len));
    check_backup_decrypt(tv, tv->expected.p, tv->expected.n, plaintext,
                         plaintext_len);
    if (tv->trailing.p) {
      memcpy(with_trailing, tv->expected.p, tv->expected.n);
      memcpy(with_trailing + tv->expected.n, tv->trailing.p, tv->trailing.n);
      check_backup_decrypt(tv, with_trailing, tv->expected.n + tv->trailing.n,
                           plaintext, plaintext_len);
    }
  }
}

int main(void) {
  test_encryption_secret();
  test_individual_secrets();
  test_derivation_paths();
  test_content_type();
  test_chacha();
  test_encrypted_backup();
  printf("bip138 vectors: %d checks, %d failed\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
