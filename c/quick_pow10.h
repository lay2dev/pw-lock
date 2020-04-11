#include "defs.h"

#define MAX_POW_N 19
#define UINT128_MAX_POW_N 38

int quick_pow10(int n, uint64_t *result) {
  static uint64_t pow10[MAX_POW_N + 1] = {
      1,
      10,
      100,
      1000,
      10000,
      100000,
      1000000,
      10000000,
      100000000,
      1000000000,
      10000000000,
      100000000000,
      1000000000000,
      10000000000000,
      100000000000000,
      1000000000000000,
      10000000000000000,
      100000000000000000,
      1000000000000000000,
      10000000000000000000U,
  };

  if (n > MAX_POW_N) {
    return 1;
  }

  *result = pow10[n];
  return 0;
}

int uint128_quick_pow10(int n, uint128_t *result) {
  if (n > UINT128_MAX_POW_N) {
    return 1;
  }

  int ret;
  uint64_t mid_result;
  if (n <= MAX_POW_N) {
    ret = quick_pow10(n, &mid_result);
    if (ret) {
      return ret;
    }
    *result = mid_result;
  } else {
    /* a^(x+y) -> a^x * a^y */
    ret = quick_pow10(n - MAX_POW_N, &mid_result);
    if (ret) {
      return ret;
    }
    *result = mid_result;
    ret = quick_pow10(MAX_POW_N, &mid_result);
    if (ret) {
      return ret;
    }
    *result *= mid_result;
  }

  return 0;
}
