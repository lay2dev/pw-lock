/* The script perform secp256k1_keccak256_sighash_all verification. */
#include "ckb_syscalls.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "secp256k1_keccak256_lock_all.h"

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
