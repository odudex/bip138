#include "bip138_internal.h"
#include <string.h>

#define PADDING_MIN 10240u
#define PADDING_MAX_STEPS 21 /* 10240 * 5^21 fits in 64 bits */

static int string_is_utf8(const uint8_t *data, size_t len) {
  size_t pos = 0;
  while (pos < len) {
    uint32_t cp = data[pos++];
    if (cp < 0x80)
      continue;
    size_t extra;
    uint32_t min;
    if (cp >= 0xc2 && cp <= 0xdf) {
      extra = 1;
      min = 0x80;
      cp &= 0x1f;
    } else if (cp >= 0xe0 && cp <= 0xef) {
      extra = 2;
      min = 0x800;
      cp &= 0x0f;
    } else if (cp >= 0xf0 && cp <= 0xf4) {
      extra = 3;
      min = 0x10000;
      cp &= 0x07;
    } else {
      return 0;
    }
    if (extra > len - pos)
      return 0;
    while (extra--) {
      uint8_t b = data[pos++];
      if ((b & 0xc0) != 0x80)
        return 0;
      cp = (cp << 6) | (b & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      return 0;
  }
  return 1;
}

size_t bip138_padding_bucket(size_t len) {
  uint64_t num = PADDING_MIN;
  uint64_t den = 1;
  for (int i = 0; i < PADDING_MAX_STEPS; i++) {
    uint64_t bucket = num / den;
    if (bucket >= len)
      return (size_t)bucket;
    num *= 5;
    den *= 4;
  }
  return 0;
}

size_t bip138_content_size(const bip138_content *content) {
  if (!content)
    return 0;
  switch (content->type) {
  case BIP138_CONTENT_BIP:
    return 3;
  case BIP138_CONTENT_STRING:
    return content->tag_len == 0 ? 2 : 0;
  case 0x00:
    return 0;
  default:
    if (content->type >= 0x80 || (!content->tag && content->tag_len > 0))
      return 0;
    if (content->tag_len > SIZE_MAX - 1 - bip138_varint_size(content->tag_len))
      return 0;
    return 1 + bip138_varint_size(content->tag_len) + content->tag_len;
  }
}

int bip138_content_encode(const bip138_content *content, uint8_t *out,
                          size_t out_cap, size_t *out_len) {
  size_t size = bip138_content_size(content);
  if (!out || !out_len)
    return BIP138_ERR_ARG;
  if (size == 0 || (content->type == BIP138_CONTENT_STRING && content->tag_len))
    return BIP138_ERR_ARG;
  if (out_cap < size)
    return BIP138_ERR_SIZE;
  out[0] = content->type;
  if (content->type == BIP138_CONTENT_BIP) {
    out[1] = (uint8_t)(content->bip >> 8);
    out[2] = (uint8_t)content->bip;
  } else {
    size_t written = 0;
    if (bip138_varint_write(out + 1, out_cap - 1, content->tag_len, &written) !=
        BIP138_OK)
      return BIP138_ERR_SIZE;
    if (content->tag_len > 0)
      memcpy(out + 1 + written, content->tag, content->tag_len);
  }
  *out_len = size;
  return BIP138_OK;
}

int bip138_content_parse(const uint8_t *buf, size_t len, bip138_content *out,
                         size_t *consumed) {
  if (!buf || !out || !consumed)
    return BIP138_ERR_ARG;
  if (len == 0 || buf[0] == 0x00 || buf[0] >= 0x80)
    return BIP138_ERR_FORMAT;
  memset(out, 0, sizeof(*out));
  out->type = buf[0];
  if (buf[0] == BIP138_CONTENT_BIP) {
    if (len < 3)
      return BIP138_ERR_FORMAT;
    out->bip = (uint16_t)((buf[1] << 8) | buf[2]);
    *consumed = 3;
    return BIP138_OK;
  }
  uint64_t tag_len = 0;
  size_t varint_len = 0;
  if (bip138_varint_read(buf + 1, len - 1, &tag_len, &varint_len) !=
          BIP138_OK ||
      tag_len > len - 1 - varint_len)
    return BIP138_ERR_FORMAT;
  if (buf[0] == BIP138_CONTENT_STRING && tag_len != 0)
    return BIP138_ERR_FORMAT;
  out->tag = buf + 1 + varint_len;
  out->tag_len = (size_t)tag_len;
  *consumed = 1 + varint_len + (size_t)tag_len;
  return BIP138_OK;
}

static size_t items_size(const bip138_item *items, size_t n_items) {
  if (!items || n_items == 0)
    return 0;
  size_t size = 0;
  for (size_t i = 0; i < n_items; i++) {
    size_t content = bip138_content_size(&items[i].content);
    if (content == 0 || !items[i].data || items[i].data_len == 0)
      return 0;
    size_t prefix = bip138_varint_size(items[i].data_len);
    if (content > SIZE_MAX - size)
      return 0;
    size += content;
    if (prefix > SIZE_MAX - size)
      return 0;
    size += prefix;
    if (items[i].data_len > SIZE_MAX - size)
      return 0;
    size += items[i].data_len;
    if (!bip138_plaintext_len_valid(size))
      return 0;
  }
  /* Validate strings only after rejecting unrepresentable lengths. */
  for (size_t i = 0; i < n_items; i++) {
    if (items[i].content.type == BIP138_CONTENT_STRING &&
        !string_is_utf8(items[i].data, items[i].data_len))
      return 0;
  }
  return size;
}

size_t bip138_plaintext_size(const bip138_item *items, size_t n_items,
                             int geometric_pad) {
  size_t size = items_size(items, n_items);
  if (size == 0 || !geometric_pad)
    return size;
  return bip138_padding_bucket(size);
}

int bip138_plaintext_encode(const bip138_item *items, size_t n_items,
                            int geometric_pad, uint8_t *out, size_t out_cap,
                            size_t *out_len) {
  size_t size = bip138_plaintext_size(items, n_items, geometric_pad);
  if (!out || !out_len)
    return BIP138_ERR_ARG;
  if (size == 0)
    return BIP138_ERR_ARG;
  if (out_cap < size)
    return BIP138_ERR_SIZE;
  size_t pos = 0;
  for (size_t i = 0; i < n_items; i++) {
    size_t written = 0;
    int ret = bip138_content_encode(&items[i].content, out + pos, out_cap - pos,
                                    &written);
    if (ret != BIP138_OK)
      return ret;
    pos += written;
    ret = bip138_varint_write(out + pos, out_cap - pos, items[i].data_len,
                              &written);
    if (ret != BIP138_OK)
      return ret;
    pos += written;
    memcpy(out + pos, items[i].data, items[i].data_len);
    pos += items[i].data_len;
  }
  memset(out + pos, 0, size - pos);
  *out_len = size;
  return BIP138_OK;
}

void bip138_item_iter_init(bip138_item_iter *it, const uint8_t *plaintext,
                           size_t len) {
  it->buf = plaintext;
  it->len = len;
  it->pos = 0;
}

int bip138_item_next(bip138_item_iter *it, bip138_item *item) {
  if (!it || !item || (!it->buf && it->len > 0))
    return BIP138_ERR_ARG;
  for (;;) {
    if (it->pos >= it->len || it->buf[it->pos] == 0x00)
      return 0;
    size_t consumed = 0;
    int ret = bip138_content_parse(it->buf + it->pos, it->len - it->pos,
                                   &item->content, &consumed);
    if (ret != BIP138_OK)
      return ret;
    size_t pos = it->pos + consumed;
    uint64_t data_len = 0;
    if (bip138_varint_read(it->buf + pos, it->len - pos, &data_len,
                           &consumed) != BIP138_OK ||
        (data_len == 0 && item->content.type <= BIP138_CONTENT_STRING) ||
        data_len > it->len - pos - consumed)
      return BIP138_ERR_FORMAT;
    pos += consumed;
    item->data = it->buf + pos;
    item->data_len = (size_t)data_len;
    if (item->content.type == BIP138_CONTENT_STRING &&
        !string_is_utf8(item->data, item->data_len))
      return BIP138_ERR_FORMAT;
    it->pos = pos + (size_t)data_len;
    if (item->content.type <= BIP138_CONTENT_STRING)
      return 1;
  }
}
