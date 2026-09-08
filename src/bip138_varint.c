#include "bip138_internal.h"

size_t bip138_varint_size(uint64_t value) {
  if (value < 0xFD)
    return 1;
  if (value <= 0xFFFF)
    return 3;
  if (value <= 0xFFFFFFFFu)
    return 5;
  return 9;
}

static void write_le(uint8_t *out, uint64_t value, size_t bytes) {
  for (size_t i = 0; i < bytes; i++)
    out[i] = (uint8_t)(value >> (8 * i));
}

int bip138_varint_write(uint8_t *out, size_t out_cap, uint64_t value,
                        size_t *written) {
  size_t size = bip138_varint_size(value);
  if (!out || !written)
    return BIP138_ERR_ARG;
  if (out_cap < size)
    return BIP138_ERR_SIZE;
  if (size == 1) {
    out[0] = (uint8_t)value;
  } else {
    out[0] = size == 3 ? 0xFD : size == 5 ? 0xFE : 0xFF;
    write_le(out + 1, value, size - 1);
  }
  *written = size;
  return BIP138_OK;
}

int bip138_varint_read(const uint8_t *buf, size_t len, uint64_t *value,
                       size_t *consumed) {
  if (!buf || !value || !consumed)
    return BIP138_ERR_ARG;
  if (len == 0)
    return BIP138_ERR_FORMAT;
  size_t size = buf[0] == 0xFD   ? 3
                : buf[0] == 0xFE ? 5
                : buf[0] == 0xFF ? 9
                                 : 1;
  if (len < size)
    return BIP138_ERR_FORMAT;
  uint64_t v = 0;
  if (size == 1) {
    v = buf[0];
  } else {
    for (size_t i = size - 1; i >= 1; i--)
      v = (v << 8) | buf[i];
  }
  if (bip138_varint_size(v) != size)
    return BIP138_ERR_FORMAT;
  *value = v;
  *consumed = size;
  return BIP138_OK;
}
