/* The script perform secp256k1_keccak256_sighash_all verification. */
#include "ckb_syscalls.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "secp256k1_keccak256_lock_all.h"

/**
 * The script args part should contain the last 20 bytes of keccak256 hash of a
 * public key, which is the same as ethereum address generation. This is used to
 * shield the real public key till the first spend.
 *
 * The first witness, or the first witness of the same index as the first input
 * cell using current lock  script, should be a
 * [WitnessArgs](https://github.com/nervosnetwork/ckb/blob/1df5f2c1cbf07e04622fb8faa5b152c1af7ae341/util/types/schemas/blockchain.mol#L106)
 * object in molecule serialization format.
 * The lock field of said WitnessArgs object should contain a 1-byte chain flag
 * and a 65-byte recoverable signature to prove ownership.
 *
 */
int main() {
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
  if (args_bytes_seg.size != LOC_ARGS_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  return verify_secp256k1_keccak_sighash_all(args_bytes_seg.ptr);
}
