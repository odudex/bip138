#include "bip138_internal.h"

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int bip138_base64_encode(const uint8_t *in, size_t len, char *out,
                         size_t out_cap, size_t *out_len) {
  if ((!in && len > 0) || !out || !out_len)
    return BIP138_ERR_ARG;
  size_t need = BIP138_BASE64_LEN(len);
  if (need == 0 || out_cap < need)
    return BIP138_ERR_SIZE;
  size_t pos = 0;
  for (size_t i = 0; i < len; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < len)
      v |= (uint32_t)in[i + 1] << 8;
    if (i + 2 < len)
      v |= in[i + 2];
    out[pos++] = alphabet[(v >> 18) & 0x3F];
    out[pos++] = alphabet[(v >> 12) & 0x3F];
    out[pos++] = i + 1 < len ? alphabet[(v >> 6) & 0x3F] : '=';
    out[pos++] = i + 2 < len ? alphabet[v & 0x3F] : '=';
  }
  out[pos] = '\0';
  *out_len = pos;
  return BIP138_OK;
}

static int decode_char(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

static int is_space(char c) {
  return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

int bip138_base64_decode(const char *in, size_t len, uint8_t *out,
                         size_t out_cap, size_t *out_len) {
  if ((!in && len > 0) || !out || !out_len)
    return BIP138_ERR_ARG;
  uint32_t acc = 0;
  int bits = 0;
  size_t pos = 0;
  size_t padding = 0;
  size_t symbols = 0;
  for (size_t i = 0; i < len; i++) {
    char c = in[i];
    if (is_space(c))
      continue;
    if (c == '=') {
      padding++;
      continue;
    }
    if (padding > 0)
      return BIP138_ERR_FORMAT;
    int v = decode_char(c);
    if (v < 0)
      return BIP138_ERR_FORMAT;
    symbols++;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (pos >= out_cap)
        return BIP138_ERR_SIZE;
      out[pos++] = (uint8_t)(acc >> bits);
    }
  }
  if ((symbols + padding) % 4 != 0 || padding > 2 || (symbols % 4) == 1)
    return BIP138_ERR_FORMAT;
  if (bits > 0 && (acc & ((1u << bits) - 1)) != 0)
    return BIP138_ERR_FORMAT;
  *out_len = pos;
  return BIP138_OK;
}
