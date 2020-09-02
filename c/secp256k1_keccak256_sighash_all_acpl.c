/* UDT anyone-can-pay lock script
 * For simplify, we call a cell with anyone-can-pay lock a wallet cell.
 *
 * Wallet cell can be unlocked without a signature, if:
 *
 * 1. There is 1 output wallet cell that has the same type hash with the
 * unlocked wallet cell.
 * 2. The UDT or CKB(if type script is none) in the output wallet is more than
 * the unlocked wallet.
 * 3. if the type script is none, the cell data is empty.
 *
 * otherwise, the script perform secp256k1_keccak256_sighash_all verification.
 */

#include "ckb_syscalls.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "secp256k1_keccak256_eth_lock.h"
#include "defs.h"
#include "quick_pow10.h"
#include "anyone_can_pay_lock.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key 
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65


#define MAX_OUTPUT_LENGTH 64

#define ERROR_TOO_MANY_OUTPUT_CELLS -18

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif


int has_signature(int *has_sig) {
  int ret;
  unsigned char temp[MAX_WITNESS_SIZE];

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);

  if ((ret == CKB_INDEX_OUT_OF_BOUND) ||
      (ret == CKB_SUCCESS && witness_len == 0)) {
    *has_sig = 0;
    return CKB_SUCCESS;
  }

  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  *has_sig = lock_bytes_seg.size > 0;
  return CKB_SUCCESS;
}


int read_args(unsigned char *pubkey_hash, uint64_t *min_ckb_amount,
              uint128_t *min_udt_amount) {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size < BLAKE160_SIZE ||
      args_bytes_seg.size > BLAKE160_SIZE + 2) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(pubkey_hash, args_bytes_seg.ptr, BLAKE160_SIZE);
  *min_ckb_amount = 0;
  *min_udt_amount = 0;
  if (args_bytes_seg.size > BLAKE160_SIZE) {
    int x = args_bytes_seg.ptr[BLAKE160_SIZE];
    int is_overflow = quick_pow10(x, min_ckb_amount);
    if (is_overflow) {
      *min_ckb_amount = MAX_UINT64;
    }
  }
  if (args_bytes_seg.size > BLAKE160_SIZE + 1) {
    int x = args_bytes_seg.ptr[BLAKE160_SIZE + 1];
    int is_overflow = uint128_quick_pow10(x, min_udt_amount);
    if (is_overflow) {
      *min_udt_amount = MAX_UINT128;
    }
  }
  return CKB_SUCCESS;
}

/*
 * Arguments:
 * ethereum address, keccak256 hash of pubkey last 20 bytes, used to
 * shield the real pubkey.
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership.
 */
int main() {

  int ret;
  int has_sig;
  unsigned char pubkey_hash[BLAKE160_SIZE];
  uint64_t min_ckb_amount;
  uint128_t min_udt_amount;
  ret = read_args(pubkey_hash, &min_ckb_amount, &min_udt_amount);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = has_signature(&has_sig);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (has_sig) {
    /* unlock via signature */
    return verify_secp256k1_keccak_eth_sighash_all(pubkey_hash);
  } else {
    /* unlock via payment */
    return check_payment_unlock(min_ckb_amount, min_udt_amount);
  }

}
