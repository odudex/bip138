#include "bip138_internal.h"
#include <string.h>

#define HARDENED 0x80000000u
#define COMMON_ACCOUNTS 10
#define COMMON_COINS 2

static const uint32_t common_purposes[] = {44, 49, 84, 86, 87};
#define COMMON_PURPOSES (sizeof(common_purposes) / sizeof(common_purposes[0]))
#define COMMON_SINGLE (COMMON_COINS * COMMON_PURPOSES * COMMON_ACCOUNTS)
#define COMMON_MULTI (COMMON_COINS * COMMON_ACCOUNTS * 2)

int bip138_path_cmp(const bip138_path *a, const bip138_path *b) {
  size_t n = a->depth < b->depth ? a->depth : b->depth;
  for (size_t i = 0; i < n; i++) {
    if (a->child[i] != b->child[i])
      return a->child[i] < b->child[i] ? -1 : 1;
  }
  return a->depth < b->depth ? -1 : a->depth > b->depth ? 1 : 0;
}

size_t bip138_paths_size(const bip138_path *paths, size_t n_paths) {
  if ((!paths && n_paths > 0) || n_paths > BIP138_MAX_COUNT)
    return 0;
  size_t size = 1;
  for (size_t i = 0; i < n_paths; i++) {
    if (!paths[i].child || paths[i].depth == 0)
      return 0;
    size += 1 + 4 * (size_t)paths[i].depth;
  }
  return size;
}

int bip138_paths_encode(const bip138_path *paths, size_t n_paths, uint8_t *out,
                        size_t out_cap, size_t *out_len) {
  uint8_t idx[BIP138_MAX_COUNT];
  if (!out || !out_len || (!paths && n_paths > 0))
    return BIP138_ERR_ARG;
  if (n_paths > BIP138_MAX_COUNT)
    return BIP138_ERR_LIMIT;
  for (size_t i = 0; i < n_paths; i++) {
    if (!paths[i].child || paths[i].depth == 0)
      return BIP138_ERR_LIMIT;
    uint8_t v = (uint8_t)i;
    size_t j = i;
    while (j > 0 && bip138_path_cmp(&paths[idx[j - 1]], &paths[v]) > 0) {
      idx[j] = idx[j - 1];
      j--;
    }
    idx[j] = v;
  }
  if (out_cap < 1)
    return BIP138_ERR_SIZE;
  size_t pos = 1;
  size_t count = 0;
  for (size_t i = 0; i < n_paths; i++) {
    const bip138_path *p = &paths[idx[i]];
    if (i > 0 && bip138_path_cmp(&paths[idx[i - 1]], p) == 0)
      continue;
    if (out_cap - pos < 1 + 4 * (size_t)p->depth)
      return BIP138_ERR_SIZE;
    out[pos++] = p->depth;
    for (size_t k = 0; k < p->depth; k++) {
      out[pos++] = (uint8_t)(p->child[k] >> 24);
      out[pos++] = (uint8_t)(p->child[k] >> 16);
      out[pos++] = (uint8_t)(p->child[k] >> 8);
      out[pos++] = (uint8_t)p->child[k];
    }
    count++;
  }
  out[0] = (uint8_t)count;
  *out_len = pos;
  return BIP138_OK;
}

static int is_hardened_in(uint32_t child, uint32_t min, uint32_t max) {
  return (child & HARDENED) && (child & ~HARDENED) >= min &&
         (child & ~HARDENED) <= max;
}

int bip138_path_is_common(const bip138_path *path) {
  if (!path || !path->child || (path->depth != 3 && path->depth != 4))
    return 0;
  if (!is_hardened_in(path->child[0], 0, 0xFFFF) ||
      !is_hardened_in(path->child[1], 0, COMMON_COINS - 1) ||
      !is_hardened_in(path->child[2], 0, COMMON_ACCOUNTS - 1))
    return 0;
  uint32_t purpose = path->child[0] & ~HARDENED;
  if (path->depth == 3) {
    for (size_t i = 0; i < COMMON_PURPOSES; i++) {
      if (purpose == common_purposes[i])
        return 1;
    }
    return 0;
  }
  return path->depth == 4 && purpose == 48 &&
         is_hardened_in(path->child[3], 1, 2);
}

size_t bip138_common_path_count(void) { return COMMON_SINGLE + COMMON_MULTI; }

int bip138_common_path(size_t index, uint32_t child[4], size_t *depth) {
  if (!child || !depth)
    return BIP138_ERR_ARG;
  if (index < COMMON_SINGLE) {
    size_t coin = index / (COMMON_PURPOSES * COMMON_ACCOUNTS);
    size_t rest = index % (COMMON_PURPOSES * COMMON_ACCOUNTS);
    child[0] = common_purposes[rest / COMMON_ACCOUNTS] | HARDENED;
    child[1] = (uint32_t)coin | HARDENED;
    child[2] = (uint32_t)(rest % COMMON_ACCOUNTS) | HARDENED;
    *depth = 3;
    return BIP138_OK;
  }
  index -= COMMON_SINGLE;
  if (index >= COMMON_MULTI)
    return BIP138_ERR_ARG;
  child[0] = 48 | HARDENED;
  child[1] = (uint32_t)(index / (COMMON_ACCOUNTS * 2)) | HARDENED;
  child[2] = (uint32_t)((index / 2) % COMMON_ACCOUNTS) | HARDENED;
  child[3] = (uint32_t)(1 + index % 2) | HARDENED;
  *depth = 4;
  return BIP138_OK;
}
