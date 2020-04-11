

#include "ckb_syscalls.h"
#include "overflow_add.h"
#include "protocol.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768
#define CKB_LEN 8
#define UDT_LEN 16
#define MAX_WITNESS_SIZE 32768
#define MAX_TYPE_HASH 256

typedef struct {
  int is_ckb_only;
  unsigned char type_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t ckb_amount;
  uint128_t udt_amount;
  uint32_t output_cnt;
} InputWallet;

int check_payment_unlock(uint64_t min_ckb_amount, uint128_t min_udt_amount) {
  unsigned char lock_hash[BLAKE2B_BLOCK_SIZE];
  InputWallet input_wallets[MAX_TYPE_HASH];
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  /* load wallet lock hash */
  int ret = ckb_load_script_hash(lock_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > BLAKE2B_BLOCK_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  /* iterate inputs and find input wallet cell */
  int i = 0;
  len = BLAKE2B_BLOCK_SIZE;
  while (1) {
    if (i >= MAX_TYPE_HASH) {
      return ERROR_TOO_MUCH_TYPE_HASH_INPUTS;
    }

    ret = ckb_checked_load_cell_by_field(input_wallets[i].type_hash, &len, 0, i,
                                         CKB_SOURCE_GROUP_INPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    if (ret == CKB_SUCCESS) {
      if (len != BLAKE2B_BLOCK_SIZE) {
        return ERROR_ENCODING;
      }
    } else if (ret != CKB_ITEM_MISSING) {
      return ERROR_SYSCALL;
    }

    input_wallets[i].is_ckb_only = ret == CKB_ITEM_MISSING;

    /* load amount */
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field(
        (uint8_t *)&input_wallets[i].ckb_amount, &len, 0, i,
        CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&input_wallets[i].udt_amount, &len, 0,
                             i, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (input_wallets[i].is_ckb_only) {
      /* ckb only wallet should has no data */
      if (len != 0) {
        return ERROR_ENCODING;
      }
    } else {
      if (len < UDT_LEN) {
        return ERROR_ENCODING;
      }
    }

    i++;
  }

  int input_wallets_cnt = i;

  /* iterate outputs wallet cell */
  i = 0;
  while (1) {
    uint8_t output_lock_hash[BLAKE2B_BLOCK_SIZE];
    uint8_t output_type_hash[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    /* check lock hash */
    ret = ckb_checked_load_cell_by_field(output_lock_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    int has_same_lock =
        memcmp(output_lock_hash, lock_hash, BLAKE2B_BLOCK_SIZE) == 0;
    if (!has_same_lock) {
      i++;
      continue;
    }
    /* load type hash */
    len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_checked_load_cell_by_field(output_type_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret == CKB_SUCCESS) {
      if (len != BLAKE2B_BLOCK_SIZE) {
        return ERROR_ENCODING;
      }
    } else if (ret != CKB_ITEM_MISSING) {
      return ERROR_SYSCALL;
    }
    int is_ckb_only = ret == CKB_ITEM_MISSING;

    /* load amount */
    uint64_t ckb_amount;
    uint128_t udt_amount;
    len = CKB_LEN;
    ret = ckb_checked_load_cell_by_field((uint8_t *)&ckb_amount, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len != CKB_LEN) {
      return ERROR_ENCODING;
    }
    len = UDT_LEN;
    ret = ckb_load_cell_data((uint8_t *)&udt_amount, &len, 0, i,
                             CKB_SOURCE_OUTPUT);
    if (ret != CKB_ITEM_MISSING && ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (is_ckb_only) {
      /* ckb only wallet should has no data */
      if (len != 0) {
        return ERROR_ENCODING;
      }
    } else {
      if (len < UDT_LEN) {
        return ERROR_ENCODING;
      }
    }

    /* find input wallet which has same type hash */
    int found_inputs = 0;
    for (int j = 0; j < input_wallets_cnt; j++) {
      int has_same_type = 0;
      /* check type hash */
      if (is_ckb_only) {
        has_same_type = input_wallets[j].is_ckb_only;
      } else {
        has_same_type = memcmp(output_type_hash, input_wallets[j].type_hash,
                               BLAKE2B_BLOCK_SIZE) == 0;
      }
      if (!has_same_type) {
        continue;
      }
      /* compare amount */
      uint64_t min_output_ckb_amount;
      uint128_t min_output_udt_amount;
      int overflow;
      overflow = uint64_overflow_add(
          &min_output_ckb_amount, input_wallets[j].ckb_amount, min_ckb_amount);
      int meet_ckb_cond = !overflow && ckb_amount >= min_output_ckb_amount;
      overflow = uint128_overflow_add(
          &min_output_udt_amount, input_wallets[j].udt_amount, min_udt_amount);
      int meet_udt_cond = !overflow && udt_amount >= min_output_udt_amount;

      /* fail if can't meet both conditions */
      if (!(meet_ckb_cond || meet_udt_cond)) {
        return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
      }
      /* output coins must meet condition, or remain the old amount */
      if ((!meet_ckb_cond && ckb_amount != input_wallets[j].ckb_amount) ||
          (!meet_udt_cond && udt_amount != input_wallets[j].udt_amount)) {

        return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
      }

      /* increase counter */
      found_inputs++;
      input_wallets[j].output_cnt += 1;
      if (found_inputs > 1) {
        return ERROR_DUPLICATED_INPUTS;
      }
      if (input_wallets[j].output_cnt > 1) {
        return ERROR_DUPLICATED_OUTPUTS;
      }
    }

    /* one output should pair with one input */
    if (found_inputs == 0) {
      return ERROR_NO_PAIR;
    } else if (found_inputs > 1) {
      return ERROR_DUPLICATED_INPUTS;
    }

    i++;
  }

  /* check inputs wallet, one input should pair with one output */
  for (int j = 0; j < input_wallets_cnt; j++) {
    if (input_wallets[j].output_cnt == 0) {
      return ERROR_NO_PAIR;
    } else if (input_wallets[j].output_cnt > 1) {
      return ERROR_DUPLICATED_OUTPUTS;
    }
  }

  return CKB_SUCCESS;
}

