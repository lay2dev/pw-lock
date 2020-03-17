#include "ckb_syscalls.h"
#include "protocol.h"

#define INPUT_SIZE 128
#define SCRIPT_SIZE 32768

int main() {
  uint64_t len = 0;
  int ret = ckb_load_cell(NULL, &len, 0, 1, CKB_SOURCE_GROUP_OUTPUT);
  if (ret != CKB_INDEX_OUT_OF_BOUND) {
    return -1;  /* 1 */
  }

  len = 0;
  ret = ckb_load_cell(NULL, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_INDEX_OUT_OF_BOUND) {
    return 0;  /* 2 */
  }

  /* 3 */
  unsigned char input[INPUT_SIZE];
  uint64_t input_len = INPUT_SIZE;
  ret = ckb_load_input(input, &input_len, 0, 0, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (input_len > INPUT_SIZE) {
    return -100;
  }

  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > SCRIPT_SIZE) {
    return -101;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return -102;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  if ((input_len == args_bytes_seg.size) &&
      (memcmp(args_bytes_seg.ptr, input, input_len) == 0)) {
    /* 4 */
    return 0;
  }
  return -103;
}