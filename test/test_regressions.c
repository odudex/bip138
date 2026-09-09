#include "bip138.h"
#include "test_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
    }                                                                          \
  } while (0)

static const uint8_t key[32] = {1};
static const uint8_t nonce[12] = {1};
static const uint8_t note[] = {3, 0, 1, 'x'};

static void check_decrypt(const uint8_t *pt, size_t len, int expected) {
  uint8_t blob[512], out[128];
  size_t blob_len = 0, out_len = 0;
  bip138_container cont;
  int ret = bip138_encrypt_ex(test_crypto(), key, 1, NULL, 0, nonce, NULL, 0,
                              pt, len, blob, sizeof(blob), &blob_len);
  CHECK(ret == BIP138_OK);
  if (ret != BIP138_OK)
    return;
  ret = bip138_parse(blob, blob_len, &cont);
  CHECK(ret == BIP138_OK);
  if (ret != BIP138_OK)
    return;
  memset(out, 0xa5, sizeof(out));
  ret = bip138_decrypt(test_crypto(), &cont, key, 1, out, sizeof(out), &out_len,
                       NULL);
  CHECK(ret == expected);
  if (ret == BIP138_OK) {
    CHECK(out_len == len && memcmp(out, pt, len) == 0);
  } else {
    for (size_t i = 0; i < len; i++)
      CHECK(out[i] == 0);
  }
}

static void test_short_paths(void) {
  for (size_t depth = 1; depth <= 2; depth++) {
    /* Exact allocation makes an accidental read past depth visible to ASan. */
    uint32_t *child = malloc(depth * sizeof(*child));
    CHECK(child != NULL);
    if (!child)
      return;
    child[0] = 0x80000054;
    if (depth == 2)
      child[1] = 0x80000000;
    bip138_path path = {child, (uint8_t)depth};
    CHECK(!bip138_path_is_common(&path));
    for (int automatic = 0; automatic <= 1; automatic++) {
      uint8_t blob[512];
      size_t blob_len = 0;
      int ret =
          automatic
              ? bip138_encrypt(test_crypto(), key, 1, &path, 1, note,
                               sizeof(note), blob, sizeof(blob), &blob_len)
              : bip138_encrypt_ex(test_crypto(), key, 1, &path, 1, nonce, NULL,
                                  0, note, sizeof(note), blob, sizeof(blob),
                                  &blob_len);
      CHECK(ret == BIP138_OK);
      if (ret != BIP138_OK)
        continue;
      bip138_container cont;
      ret = bip138_parse(blob, blob_len, &cont);
      CHECK(ret == BIP138_OK);
      if (ret != BIP138_OK)
        continue;
      CHECK(cont.path_count == 1);
      uint32_t restored[2];
      size_t restored_depth = 0;
      CHECK(bip138_path_at(&cont, 0, restored, 2, &restored_depth) ==
            BIP138_OK);
      CHECK(restored_depth == depth && memcmp(restored, child, depth * 4) == 0);
    }
    free(child);
  }
  uint32_t child = 0;
  bip138_path empty = {&child, 0};
  CHECK(!bip138_path_is_common(&empty));
  CHECK(!bip138_path_is_common(NULL));
}

static int callback_calls;

static int unexpected_aead(void *ctx, const uint8_t k[32], const uint8_t n[12],
                           const uint8_t *in, size_t len, uint8_t *out) {
  (void)ctx;
  (void)k;
  (void)n;
  (void)in;
  (void)len;
  (void)out;
  callback_calls++;
  return -1;
}

static void test_size_limits(void) {
  uint8_t out[128];
  size_t len = 0;
  const size_t excessive[] = {SIZE_MAX, SIZE_MAX - 1, SIZE_MAX - 4};
  bip138_crypto probe = *test_crypto();
  probe.aead_encrypt = unexpected_aead;
  probe.aead_decrypt = unexpected_aead;
  for (size_t i = 0; i < sizeof(excessive) / sizeof(excessive[0]); i++) {
    size_t n = excessive[i];
    CHECK(bip138_encrypt_ex(test_crypto(), key, 1, NULL, 0, nonce, NULL, n,
                            note, sizeof(note), out, sizeof(out),
                            &len) == BIP138_ERR_LIMIT);
    CHECK(bip138_encrypt_size(n, NULL, 0, sizeof(note)) == 0);
    CHECK(bip138_encrypt_size(1, NULL, 0, n) == 0);
    CHECK(bip138_encrypt_ex(&probe, key, 1, NULL, 0, nonce, NULL, 0, note, n,
                            out, sizeof(out), &len) != BIP138_OK);
    CHECK(bip138_payload_encrypt(&probe, key, nonce, note, n, out,
                                 sizeof(out)) != BIP138_OK);
    bip138_item item = {{BIP138_CONTENT_BIP, 380, NULL, 0}, note, n};
    CHECK(bip138_plaintext_size(&item, 1, 0) == 0);
    CHECK(bip138_plaintext_encode(&item, 1, 0, out, sizeof(out), &len) ==
          BIP138_ERR_ARG);
    bip138_content content = {BIP138_CONTENT_PROPRIETARY, 0, note, n};
    CHECK(bip138_content_size(&content) == 0);
    CHECK(bip138_content_encode(&content, out, sizeof(out), &len) ==
          BIP138_ERR_ARG);
    CHECK(BIP138_BASE64_LEN(n) == 0);
    CHECK(bip138_base64_encode(note, n, (char *)out, sizeof(out), &len) ==
          BIP138_ERR_SIZE);
  }
  bip138_item items[2] = {
      {{BIP138_CONTENT_BIP, 380, NULL, 0}, note, SIZE_MAX / 2},
      {{BIP138_CONTENT_BIP, 329, NULL, 0}, note, SIZE_MAX / 2}};
  CHECK(bip138_plaintext_size(items, 2, 0) == 0);
  CHECK(bip138_plaintext_encode(items, 2, 0, out, sizeof(out), &len) ==
        BIP138_ERR_ARG);
  CHECK(bip138_encrypt_size(0, NULL, 0, sizeof(note)) == 0);
  CHECK(bip138_encrypt_size(1, NULL, 0, 0) == 0);
  CHECK(bip138_encrypt_size(1, NULL, 1, sizeof(note)) == 0);
  uint32_t child = 1;
  bip138_path path = {&child, 1};
  CHECK(bip138_encrypt_size(1, &path, SIZE_MAX, sizeof(note)) == 0);
  path.depth = 0;
  CHECK(bip138_encrypt_size(1, &path, 1, sizeof(note)) == 0);
  CHECK(bip138_encrypt_ex(test_crypto(), key, 1, NULL, 0, nonce, NULL, 255,
                          note, sizeof(note), out, sizeof(out),
                          &len) == BIP138_ERR_LIMIT);
  CHECK(BIP138_BASE64_LEN(((SIZE_MAX - 1) / 4) * 3) != 0);
  CHECK(BIP138_BASE64_LEN(((SIZE_MAX - 1) / 4) * 3 + 1) == 0);
  CHECK(bip138_payload_encrypt(&probe, key, nonce, note, sizeof(note), out,
                               15) == BIP138_ERR_SIZE);
  CHECK(bip138_payload_encrypt(&probe, key, nonce, note, sizeof(note), out,
                               sizeof(note) + BIP138_TAG_LEN - 1) ==
        BIP138_ERR_SIZE);
#if SIZE_MAX > UINT32_MAX
  size_t max_pt = (UINT64_C(1) << 38) - 64;
  CHECK(bip138_encrypt_size(1, NULL, 0, max_pt) > max_pt);
  CHECK(bip138_encrypt_size(1, NULL, 0, max_pt + 1) == 0);
  CHECK(bip138_payload_encrypt(&probe, key, nonce, note, max_pt + 1, out,
                               SIZE_MAX) == BIP138_ERR_LIMIT);
  CHECK(bip138_payload_decrypt(&probe, key, nonce, note, max_pt + 17, out,
                               SIZE_MAX) == BIP138_ERR_LIMIT);
  bip138_container cont = {0};
  cont.ciphertext_len = max_pt + 17;
  CHECK(bip138_plaintext_max(&cont) == 0);
#endif
  CHECK(callback_calls == 0);
}

static void test_unknown_content(void) {
  const uint8_t unknown[] = {5, 0, 1, 0xff};
  const uint8_t padded[] = {5, 0, 1, 0xff, 0, 0x80, 0xff};
  const uint8_t empty_unknown_known[] = {5, 0, 0, 3, 0, 1, 'x'};
  const uint8_t padding_only[] = {0, 3, 0, 1, 'x'};
  const uint8_t truncated[] = {5, 0, 1};
  const uint8_t trailing_truncated[] = {5, 0, 1, 'x', 5};
  const uint8_t upgrade[] = {5, 0, 1, 'x', 0x80, 0, 1, 'y'};
  check_decrypt(unknown, sizeof(unknown), BIP138_OK);
  check_decrypt(padded, sizeof(padded), BIP138_OK);
  check_decrypt(empty_unknown_known, sizeof(empty_unknown_known), BIP138_OK);
  check_decrypt(padding_only, sizeof(padding_only), BIP138_ERR_FORMAT);
  check_decrypt(truncated, sizeof(truncated), BIP138_ERR_FORMAT);
  check_decrypt(trailing_truncated, sizeof(trailing_truncated),
                BIP138_ERR_FORMAT);
  check_decrypt(upgrade, sizeof(upgrade), BIP138_ERR_FORMAT);
  bip138_item_iter it;
  bip138_item item;
  bip138_item_iter_init(&it, unknown, sizeof(unknown));
  CHECK(bip138_item_next(&it, &item) == 0);
  bip138_item_iter_init(&it, empty_unknown_known, sizeof(empty_unknown_known));
  CHECK(bip138_item_next(&it, &item) == 1);
  CHECK(item.content.type == BIP138_CONTENT_STRING && item.data_len == 1 &&
        item.data[0] == 'x');
  CHECK(bip138_item_next(&it, &item) == 0);
}

static void test_utf8(void) {
  static const struct {
    uint8_t data[5];
    size_t len;
    int valid;
  } cases[] = {
      {{0}, 1, 1},
      {{0x7f}, 1, 1},
      {{0xc2, 0x80}, 2, 1},
      {{0xdf, 0xbf}, 2, 1},
      {{0xe0, 0xa0, 0x80}, 3, 1},
      {{0xed, 0x9f, 0xbf}, 3, 1},
      {{0xee, 0x80, 0x80}, 3, 1},
      {{0xef, 0xbf, 0xbf}, 3, 1},
      {{0xf0, 0x90, 0x80, 0x80}, 4, 1},
      {{0xf4, 0x8f, 0xbf, 0xbf}, 4, 1},
      {{0xff}, 1, 0},
      {{0x80}, 1, 0},
      {{0xbf}, 1, 0},
      {{0xc0, 0x80}, 2, 0},
      {{0xc1, 0xbf}, 2, 0},
      {{0xe0, 0x80, 0x80}, 3, 0},
      {{0xf0, 0x80, 0x80, 0x80}, 4, 0},
      {{0xed, 0xa0, 0x80}, 3, 0},
      {{0xed, 0xbf, 0xbf}, 3, 0},
      {{0xf4, 0x90, 0x80, 0x80}, 4, 0},
      {{0xf5, 0x80, 0x80, 0x80}, 4, 0},
      {{0xf8, 0x88, 0x80, 0x80, 0x80}, 5, 0},
      {{0xc2}, 1, 0},
      {{0xe0, 0xa0}, 2, 0},
      {{0xf0, 0x90, 0x80}, 3, 0},
      {{0xc2, 'x'}, 2, 0},
      {{0xef, 0xbf, 'x'}, 3, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    bip138_item item = {
        {BIP138_CONTENT_STRING, 0, NULL, 0}, cases[i].data, cases[i].len};
    uint8_t encoded[32];
    size_t len = 0;
    CHECK((bip138_plaintext_size(&item, 1, 0) != 0) == cases[i].valid);
    CHECK(
        bip138_plaintext_encode(&item, 1, 0, encoded, sizeof(encoded), &len) ==
        (cases[i].valid ? BIP138_OK : BIP138_ERR_ARG));
    /* Build raw framing to test rejection during decode independently. */
    encoded[0] = BIP138_CONTENT_STRING;
    encoded[1] = 0;
    encoded[2] = (uint8_t)cases[i].len;
    memcpy(encoded + 3, cases[i].data, cases[i].len);
    len = 3 + cases[i].len;
    bip138_item_iter it;
    bip138_item_iter_init(&it, encoded, len);
    CHECK(bip138_item_next(&it, &item) ==
          (cases[i].valid ? 1 : BIP138_ERR_FORMAT));
    check_decrypt(encoded, len, cases[i].valid ? BIP138_OK : BIP138_ERR_FORMAT);
    /* The same bytes remain legal opaque vendor content. */
    encoded[0] = BIP138_CONTENT_PROPRIETARY;
    check_decrypt(encoded, len, BIP138_OK);
  }
}

/* Repeated stored secrets, allowed by the BIP's SHOULD, must not multiply the
 * trial decryptions and must still open. */
static void test_duplicate_secrets(void) {
  uint8_t blob[512], out[128], dup[1024];
  size_t blob_len = 0, out_len = 0;
  bip138_container cont;
  CHECK(bip138_encrypt_ex(test_crypto(), key, 1, NULL, 0, nonce, NULL, 0, note,
                          sizeof(note), blob, sizeof(blob),
                          &blob_len) == BIP138_OK);
  CHECK(bip138_parse(blob, blob_len, &cont) == BIP138_OK);
  CHECK(cont.secret_count == 1);
  /* Rebuild the container with the single real secret repeated 8 times. */
  size_t head = (size_t)(cont.secrets - blob) - 1;
  size_t tail_off = (size_t)(cont.secrets + BIP138_SECRET_LEN - blob);
  size_t tail_len = blob_len - tail_off;
  memcpy(dup, blob, head);
  dup[head] = 8;
  for (int i = 0; i < 8; i++)
    memcpy(dup + head + 1 + i * BIP138_SECRET_LEN, cont.secrets,
           BIP138_SECRET_LEN);
  memcpy(dup + head + 1 + 8 * BIP138_SECRET_LEN, blob + tail_off, tail_len);
  size_t dup_len = head + 1 + 8 * BIP138_SECRET_LEN + tail_len;
  CHECK(bip138_parse(dup, dup_len, &cont) == BIP138_OK);
  CHECK(cont.secret_count == 8);
  callback_calls = 0;
  bip138_crypto counting = *test_crypto();
  counting.aead_decrypt = unexpected_aead; /* fails: counts attempts only */
  CHECK(bip138_decrypt(&counting, &cont, key, 1, out, sizeof(out), &out_len,
                       NULL) == BIP138_ERR_NO_KEY);
  CHECK(callback_calls == 1);
  CHECK(bip138_decrypt(test_crypto(), &cont, key, 1, out, sizeof(out), &out_len,
                       NULL) == BIP138_OK);
  CHECK(out_len == sizeof(note) && memcmp(out, note, out_len) == 0);
}

/* A zero-length (or otherwise sub-tag) ciphertext is well framed, so the parser
 * accepts it; the AEAD rejects it at decrypt, keeping the parser agnostic to the
 * encryption algorithm. */
static void test_zero_length_ciphertext(void) {
  uint8_t blob[64];
  size_t n = 0;
  memcpy(blob + n, BIP138_MAGIC, BIP138_MAGIC_LEN);
  n += BIP138_MAGIC_LEN;
  blob[n++] = BIP138_VERSION;                        /* version */
  blob[n++] = 0x00;                                  /* 0 derivation paths */
  blob[n++] = 0x01;                                  /* 1 individual secret */
  memset(blob + n, 0xAB, BIP138_SECRET_LEN);
  n += BIP138_SECRET_LEN;
  blob[n++] = BIP138_ENCRYPTION_CHACHA20_POLY1305;   /* encryption */
  memset(blob + n, 0x01, BIP138_NONCE_LEN);          /* non-zero nonce */
  n += BIP138_NONCE_LEN;
  blob[n++] = 0x00;                                  /* ciphertext length = 0 */

  bip138_container cont;
  CHECK(bip138_parse(blob, n, &cont) == BIP138_OK);
  CHECK(cont.ciphertext_len == 0);

  uint8_t out[64];
  size_t out_len = 0;
  /* Deferred: the empty ciphertext fails at decrypt, not at parse. */
  CHECK(bip138_decrypt(test_crypto(), &cont, key, 1, out, sizeof(out), &out_len,
                       NULL) != BIP138_OK);
}

int main(void) {
  test_short_paths();
  test_size_limits();
  test_unknown_content();
  test_utf8();
  test_duplicate_secrets();
  test_zero_length_ciphertext();
  printf("bip138 regressions: %d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
