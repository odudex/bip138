#include "bip138.h"
#include "test_crypto.h"
#include "vectors.h"
#include <stdio.h>
#include <stdlib.h>
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

#define HARDENED 0x80000000u

static const uint8_t keys[3 * BIP138_KEY_LEN] = {
    [0] = 0x11, [1] = 0x22, [32] = 0xaa, [33] = 0xbb, [64] = 0x33, [65] = 0x44};
static const uint8_t foreign_key[BIP138_KEY_LEN] = {[0] = 0x99};
static const uint32_t common_child[] = {84 | HARDENED, 0 | HARDENED,
                                        0 | HARDENED};
static const uint32_t custom_child[] = {84 | HARDENED, 0 | HARDENED,
                                        10 | HARDENED};
static const bip138_path paths[2] = {{common_child, 3}, {custom_child, 3}};
static const char descriptor[] = "wpkh(xpub/<0;1>/*)";
static const char labels[] = "{\"type\":\"tx\"}";

static size_t build_plaintext(uint8_t *out, size_t cap, int pad) {
  bip138_item items[2] = {{{BIP138_CONTENT_BIP, BIP138_BIP_DESCRIPTOR, NULL, 0},
                           (const uint8_t *)descriptor,
                           sizeof(descriptor) - 1},
                          {{BIP138_CONTENT_BIP, BIP138_BIP_LABELS, NULL, 0},
                           (const uint8_t *)labels,
                           sizeof(labels) - 1}};
  size_t len = 0;
  if (bip138_plaintext_encode(items, 2, pad, out, cap, &len) != BIP138_OK)
    return 0;
  return len;
}

static void test_round_trip(void) {
  const bip138_crypto *c = test_crypto();
  uint8_t plaintext[256];
  uint8_t out[1024];
  uint8_t pt[256];
  size_t plaintext_len = build_plaintext(plaintext, sizeof(plaintext), 0);
  size_t out_len = 0;
  size_t pt_len = 0;
  size_t key_index = 99;
  bip138_container cont;

  CHECK("plaintext", plaintext_len > 0);
  size_t bound =
      bip138_encrypt_size(bip138_secret_bucket(3), paths, 2, plaintext_len);
  CHECK("bound fits", bound <= sizeof(out));
  CHECK("encrypt",
        bip138_encrypt(c, keys, 3, paths, 2, plaintext, plaintext_len, out,
                       sizeof(out), &out_len) == BIP138_OK);
  CHECK("bound holds", out_len <= bound);
  CHECK("parse", bip138_parse(out, out_len, &cont) == BIP138_OK);
  CHECK("common path dropped", cont.path_count == 1);
  CHECK("keep flag", bip138_encrypt_flags(c, keys, 3, paths, 2,
                                          BIP138_FLAG_KEEP_COMMON_PATHS,
                                          plaintext, plaintext_len, out,
                                          sizeof(out), &out_len) == BIP138_OK);
  CHECK("common path kept",
        bip138_parse(out, out_len, &cont) == BIP138_OK && cont.path_count == 2);
  CHECK("encrypt again",
        bip138_encrypt(c, keys, 3, paths, 2, plaintext, plaintext_len, out,
                       sizeof(out), &out_len) == BIP138_OK);
  CHECK("parse again", bip138_parse(out, out_len, &cont) == BIP138_OK);
  CHECK("decoys to bucket", cont.secret_count == 5);
  uint32_t child[8];
  size_t depth = 0;
  CHECK("path_at", bip138_path_at(&cont, 0, child, 8, &depth) == BIP138_OK);
  CHECK("path kept", depth == 3 && memcmp(child, custom_child, 12) == 0);
  CHECK("path_at oob",
        bip138_path_at(&cont, 1, child, 8, &depth) == BIP138_ERR_ARG);
  for (size_t i = 1; i < cont.secret_count; i++) {
    CHECK("secrets sorted",
          memcmp(cont.secrets + (i - 1) * 32, cont.secrets + i * 32, 32) < 0);
  }
  for (size_t i = 0; i < cont.secret_count; i++) {
    uint8_t acc = 0;
    for (size_t b = 0; b < 32; b++)
      acc |= cont.secrets[i * 32 + b];
    CHECK("secret nonzero", acc != 0);
  }
  uint8_t nonce_acc = 0;
  for (size_t b = 0; b < BIP138_NONCE_LEN; b++)
    nonce_acc |= cont.nonce[b];
  CHECK("nonce nonzero", nonce_acc != 0);

  CHECK("decrypt key 1", bip138_decrypt(c, &cont, keys + 32, 1, pt, sizeof(pt),
                                        &pt_len, &key_index) == BIP138_OK);
  CHECK("plaintext back",
        pt_len == plaintext_len && memcmp(pt, plaintext, pt_len) == 0);
  CHECK("key index", key_index == 0);
  uint8_t candidates[2 * BIP138_KEY_LEN];
  memcpy(candidates, foreign_key, 32);
  memcpy(candidates + 32, keys + 64, 32);
  CHECK("second candidate",
        bip138_decrypt(c, &cont, candidates, 2, pt, sizeof(pt), &pt_len,
                       &key_index) == BIP138_OK);
  CHECK("key index 1", key_index == 1);
  CHECK("foreign fails",
        bip138_decrypt(c, &cont, foreign_key, 1, pt, sizeof(pt), &pt_len,
                       NULL) == BIP138_ERR_NO_KEY);
  CHECK("small plaintext",
        bip138_decrypt(c, &cont, keys, 3, pt, bip138_plaintext_max(&cont) - 1,
                       &pt_len, NULL) == BIP138_ERR_SIZE);

  bip138_item_iter it;
  bip138_item item;
  CHECK("decrypt again", bip138_decrypt(c, &cont, keys, 3, pt, sizeof(pt),
                                        &pt_len, NULL) == BIP138_OK);
  bip138_item_iter_init(&it, pt, pt_len);
  CHECK("item 1", bip138_item_next(&it, &item) == 1);
  CHECK("item 1 type", item.content.type == BIP138_CONTENT_BIP &&
                           item.content.bip == BIP138_BIP_DESCRIPTOR);
  CHECK("item 1 data", item.data_len == sizeof(descriptor) - 1 &&
                           memcmp(item.data, descriptor, item.data_len) == 0);
  CHECK("item 2", bip138_item_next(&it, &item) == 1);
  CHECK("item 2 type", item.content.bip == BIP138_BIP_LABELS);
  CHECK("end", bip138_item_next(&it, &item) == 0);

  uint8_t nums[BIP138_KEY_LEN] = {
      0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b,
      0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec,
      0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};
  CHECK("nums only",
        bip138_encrypt(c, nums, 1, NULL, 0, plaintext, plaintext_len, out,
                       sizeof(out), &out_len) == BIP138_ERR_ARG);
  CHECK("empty plaintext",
        bip138_encrypt(c, keys, 3, NULL, 0, plaintext, 0, out, sizeof(out),
                       &out_len) == BIP138_ERR_ARG);
}

static void test_sizes(void) {
  const bip138_crypto *c = test_crypto();
  uint8_t plaintext[256];
  uint8_t out[1024];
  uint8_t decoys[2 * BIP138_SECRET_LEN] = {[0] = 1, [32] = 2};
  uint8_t nonce[BIP138_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  size_t plaintext_len = build_plaintext(plaintext, sizeof(plaintext), 0);
  size_t out_len = 0;

  CHECK("encrypt_ex", bip138_encrypt_ex(c, keys, 3, paths, 2, nonce, decoys, 2,
                                        plaintext, plaintext_len, out,
                                        sizeof(out), &out_len) == BIP138_OK);
  CHECK("exact size",
        bip138_encrypt_size(5, paths, 2, plaintext_len) >= out_len);
  for (size_t cap = 0; cap < out_len; cap += 7) {
    size_t len = 0;
    CHECK("short buffer",
          bip138_encrypt_ex(c, keys, 3, paths, 2, nonce, decoys, 2, plaintext,
                            plaintext_len, out, cap, &len) == BIP138_ERR_SIZE);
  }
  CHECK("short plaintext",
        build_plaintext(plaintext, plaintext_len - 1, 0) == 0);

  char b64[2048];
  size_t b64_len = 0;
  CHECK("b64 short",
        bip138_base64_encode(out, out_len, b64, BIP138_BASE64_LEN(out_len) - 1,
                             &b64_len) == BIP138_ERR_SIZE);
  CHECK("b64", bip138_base64_encode(out, out_len, b64, sizeof(b64), &b64_len) ==
                   BIP138_OK);
  CHECK("b64 len",
        b64_len == BIP138_BASE64_LEN(out_len) - 1 && strlen(b64) == b64_len);
  uint8_t decoded[1024];
  size_t decoded_len = 0;
  CHECK("b64 decode short",
        bip138_base64_decode(b64, b64_len, decoded, out_len - 1,
                             &decoded_len) == BIP138_ERR_SIZE);
  CHECK("b64 decode",
        bip138_base64_decode(b64, b64_len, decoded, sizeof(decoded),
                             &decoded_len) == BIP138_OK);
  CHECK("b64 round trip",
        decoded_len == out_len && memcmp(decoded, out, out_len) == 0);
}

static void test_buckets(void) {
  CHECK("pad 0", bip138_padding_bucket(0) == 10240);
  CHECK("pad 10240", bip138_padding_bucket(10240) == 10240);
  CHECK("pad 10241", bip138_padding_bucket(10241) == 12800);
  CHECK("pad 12801", bip138_padding_bucket(12801) == 16000);
  CHECK("pad 16001", bip138_padding_bucket(16001) == 20000);
  CHECK("pad 39063", bip138_padding_bucket(39063) == 48828);
  static const size_t secret_cases[][2] = {
      {0, 0},     {1, 5},     {5, 5},   {6, 10},   {10, 10},
      {11, 20},   {21, 40},   {80, 80}, {81, 160}, {160, 160},
      {161, 255}, {255, 255}, {256, 0}};
  for (size_t i = 0; i < sizeof(secret_cases) / sizeof(secret_cases[0]); i++) {
    CHECK("secret bucket",
          bip138_secret_bucket(secret_cases[i][0]) == secret_cases[i][1]);
  }

  static uint8_t padded[16384];
  size_t len = build_plaintext(padded, sizeof(padded), 1);
  CHECK("padded size", len == 10240);
  bip138_item_iter it;
  bip138_item item;
  bip138_item_iter_init(&it, padded, len);
  CHECK("padded item 1", bip138_item_next(&it, &item) == 1);
  CHECK("padded item 2", bip138_item_next(&it, &item) == 1);
  CHECK("padded end", bip138_item_next(&it, &item) == 0);
}

static void test_common_paths(void) {
  CHECK("count", bip138_common_path_count() == 140);
  uint8_t out[4096];
  size_t out_len = 0;
  bip138_path all[140];
  uint32_t children[140][4];
  for (size_t i = 0; i < 140; i++) {
    size_t depth = 0;
    CHECK("common_path",
          bip138_common_path(i, children[i], &depth) == BIP138_OK);
    all[i].child = children[i];
    all[i].depth = (uint8_t)depth;
    CHECK("is_common", bip138_path_is_common(&all[i]));
    for (size_t j = 0; j < i; j++)
      CHECK("distinct", !(all[j].depth == depth &&
                          memcmp(children[j], children[i], 4 * depth) == 0));
  }
  size_t depth = 0;
  uint32_t child[4];
  CHECK("oob", bip138_common_path(140, child, &depth) == BIP138_ERR_ARG);
  CHECK("custom not common", !bip138_path_is_common(&paths[1]));
  const uint32_t unhardened[] = {84, 0 | HARDENED, 0 | HARDENED};
  const bip138_path p = {unhardened, 3};
  CHECK("unhardened not common", !bip138_path_is_common(&p));
  CHECK("encode all",
        bip138_paths_encode(all, 140, out, sizeof(out), &out_len) == BIP138_OK);
  CHECK("encode count", out[0] == 140);
}

static void test_payload_parsing(void) {
  static const uint8_t skip_unknown[] = {0x05, 0x02, 0xaa, 0xbb, 0x01,
                                         'x',  0x01, 0x01, 0x7c, 0x01,
                                         'y',  0x00, 0xff, 0xff};
  static const uint8_t reject_high[] = {0x80, 0x00, 0x01, 'x'};
  static const uint8_t truncated[] = {0x01, 0x01, 0x7c, 0x05, 'y'};
  static const uint8_t zero_len[] = {0x01, 0x01, 0x7c, 0x00};
  bip138_item_iter it;
  bip138_item item;

  bip138_item_iter_init(&it, skip_unknown, sizeof(skip_unknown));
  CHECK("skip unknown", bip138_item_next(&it, &item) == 1);
  CHECK("known item", item.content.bip == 380 && item.data[0] == 'y');
  CHECK("terminator", bip138_item_next(&it, &item) == 0);

  bip138_item_iter_init(&it, reject_high, sizeof(reject_high));
  CHECK("reject >= 0x80", bip138_item_next(&it, &item) == BIP138_ERR_FORMAT);
  bip138_item_iter_init(&it, truncated, sizeof(truncated));
  CHECK("truncated", bip138_item_next(&it, &item) == BIP138_ERR_FORMAT);
  bip138_item_iter_init(&it, zero_len, sizeof(zero_len));
  CHECK("zero length", bip138_item_next(&it, &item) == BIP138_ERR_FORMAT);
  bip138_item_iter_init(&it, NULL, 0);
  CHECK("empty", bip138_item_next(&it, &item) == 0);
}

static void test_base64_edges(void) {
  uint8_t out[64];
  size_t len = 0;
  CHECK("whitespace", bip138_base64_decode(" QklQ\nMTM4 \r\n", 13, out,
                                           sizeof(out), &len) == BIP138_OK);
  CHECK("whitespace value", len == 6 && memcmp(out, "BIP138", 6) == 0);
  CHECK("bad char", bip138_base64_decode("QklQ*TM4", 8, out, sizeof(out),
                                         &len) == BIP138_ERR_FORMAT);
  CHECK("bad padding", bip138_base64_decode("QklQM===", 8, out, sizeof(out),
                                            &len) == BIP138_ERR_FORMAT);
  CHECK("pad then data", bip138_base64_decode("QklQ=TM4", 8, out, sizeof(out),
                                              &len) == BIP138_ERR_FORMAT);
  CHECK("bad length", bip138_base64_decode("QklQM", 5, out, sizeof(out),
                                           &len) == BIP138_ERR_FORMAT);
  CHECK("empty",
        bip138_base64_decode("", 0, out, sizeof(out), &len) == BIP138_OK &&
            len == 0);
  char text[16];
  CHECK("encode empty",
        bip138_base64_encode(NULL, 0, text, sizeof(text), &len) == BIP138_OK &&
            len == 0 && text[0] == '\0');
}

static void test_failing_crypto(void) {
  const bip138_crypto *bad = test_crypto_failing();
  uint8_t plaintext[256];
  uint8_t out[1024];
  size_t plaintext_len = build_plaintext(plaintext, sizeof(plaintext), 0);
  size_t out_len = 0;
  CHECK("encrypt fails",
        bip138_encrypt(bad, keys, 3, NULL, 0, plaintext, plaintext_len, out,
                       sizeof(out), &out_len) == BIP138_ERR_CRYPTO);
  bip138_container cont;
  const tv_backup *tv = &tv_backup_vectors[0];
  CHECK("parse",
        bip138_parse(tv->expected.p, tv->expected.n, &cont) == BIP138_OK);
  CHECK("decrypt fails", bip138_decrypt(bad, &cont, keys, 1, out, sizeof(out),
                                        &out_len, NULL) == BIP138_ERR_CRYPTO);
  CHECK("secret fails",
        bip138_decryption_secret(bad, keys, 3, out) == BIP138_ERR_CRYPTO);
}

static void test_non_minimal_varint(void) {
  const tv_backup *tv = &tv_backup_vectors[0];
  uint8_t buf[512];
  bip138_container cont;
  CHECK("parse",
        bip138_parse(tv->expected.p, tv->expected.n, &cont) == BIP138_OK);
  size_t varint_at = (size_t)(cont.ciphertext - tv->expected.p) - 1;
  CHECK("one-byte varint", tv->expected.p[varint_at] == cont.ciphertext_len);
  memcpy(buf, tv->expected.p, varint_at);
  buf[varint_at] = 0xfd;
  buf[varint_at + 1] = (uint8_t)cont.ciphertext_len;
  buf[varint_at + 2] = 0;
  memcpy(buf + varint_at + 3, cont.ciphertext, cont.ciphertext_len);
  CHECK("non-minimal rejected",
        bip138_parse(buf, varint_at + 3 + cont.ciphertext_len, &cont) ==
            BIP138_ERR_FORMAT);
}

/* A mutated container must either fail cleanly or still decrypt to the
 * original plaintext (a flipped decoy changes nothing). */
static void check_mutation(const uint8_t *buf, size_t len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *key) {
  const bip138_crypto *c = test_crypto();
  bip138_container cont;
  uint8_t pt[512];
  size_t pt_len = 0;
  if (bip138_parse(buf, len, &cont) != BIP138_OK)
    return;
  int ret = bip138_decrypt(c, &cont, key, 1, pt, sizeof(pt), &pt_len, NULL);
  if (ret == BIP138_OK) {
    CHECK("mutation",
          pt_len == plaintext_len && memcmp(pt, plaintext, plaintext_len) == 0);
  }
}

static void test_corruption(void) {
  const bip138_crypto *c = test_crypto();
  const tv_backup *tv = &tv_backup_vectors[0];
  uint8_t plaintext[64];
  uint8_t buf[512];
  size_t pt_len = 0;
  bip138_container cont;

  CHECK("parse",
        bip138_parse(tv->expected.p, tv->expected.n, &cont) == BIP138_OK);
  CHECK("decrypt",
        bip138_decrypt(c, &cont, tv->keys.p, 1, plaintext, sizeof(plaintext),
                       &pt_len, NULL) == BIP138_OK);

  for (size_t i = 0; i < tv->expected.n; i++) {
    for (int bit = 0; bit < 8; bit++) {
      memcpy(buf, tv->expected.p, tv->expected.n);
      buf[i] ^= (uint8_t)(1 << bit);
      check_mutation(buf, tv->expected.n, plaintext, pt_len, tv->keys.p);
    }
  }
  for (size_t len = 0; len < tv->expected.n; len++) {
    CHECK("truncated", bip138_parse(tv->expected.p, len, &cont) != BIP138_OK);
  }
  uint32_t state = 0x1234567u;
  for (int round = 0; round < 2000; round++) {
    memcpy(buf, tv->expected.p, tv->expected.n);
    state = state * 1664525u + 1013904223u;
    int n = 1 + (int)((state >> 24) % 4);
    for (int k = 0; k < n; k++) {
      state = state * 1664525u + 1013904223u;
      buf[(state >> 8) % tv->expected.n] = (uint8_t)(state >> 24);
    }
    check_mutation(buf, tv->expected.n, plaintext, pt_len, tv->keys.p);
  }
}

int main(void) {
  test_round_trip();
  test_sizes();
  test_buckets();
  test_common_paths();
  test_payload_parsing();
  test_base64_edges();
  test_failing_crypto();
  test_non_minimal_varint();
  test_corruption();
  printf("bip138 api: %d checks, %d failed\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
