#include "ckb_syscalls.h"
#include "protocol.h"

#define INPUT_SIZE 128
#define SCRIPT_SIZE 32768
#define HASH_SIZE 32


#define ERROR_SYSCALL -4


/* the simple otx lock script only for one scenario:  
   1. otx.inputs.length === otx.outputs.length 
*/

int main()
{
  /*load script args*/
  unsigned char script[SCRIPT_SIZE];
  unsigned char script_hash[HASH_SIZE];
  unsigned char current_script_hash[HASH_SIZE];
  unsigned char tx_hash[HASH_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS)
  {
    return ret;
  }
  if (len > SCRIPT_SIZE)
  {
    return -101;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK)
  {
    return -102;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  /* load script hash*/
  len = HASH_SIZE;
  ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }

  /* calculate hash  = all input with the same lock script hash  + all output of same index with input*/

  size_t index = 0;
  while (1)
  {
    ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);

    if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
      break;
    }

    if (ret == CKB_ITEM_MISSING)
    {
      index += 1;
      continue;
    }

    if (ret != CKB_SUCCESS)
    {
      return ret;
    }

    if (len != HASH_SIZE)
    {
      return -103;
    }

    /* check current input lock script hash equals script hash*/
    if ((len == HASH_SIZE) &&
        (memcmp(current_script_hash, script_hash, HASH_SIZE) == 0))
    {

      /* input: previous_outpoint + since */
      /* output: capacity + lock_script_hash + type_script_hash + output_data */

    }

    index += 1;
  }

  /* verify signature using tx_hash*/



  return -104;
}