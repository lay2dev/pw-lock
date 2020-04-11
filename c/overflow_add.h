#include "defs.h"

int uint64_overflow_add(uint64_t *result, uint64_t a, uint64_t b) {
  if (MAX_UINT64 - a < b) {
    /* overflow */
    return 1;
  }
  *result = a + b;
  return 0;
}

int uint128_overflow_add(uint128_t *result, uint128_t a, uint128_t b) {
  if (MAX_UINT128 - a < b) {
    /* overflow */
    return 1;
  }
  *result = a + b;
  return 0;
}
