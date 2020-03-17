#include "ckb_syscalls.h"
#include "protocol.h"

#define INPUT_SIZE 128
#define SCRIPT_SIZE 32768
#define HASH_SIZE 32

int main()
{
  /*load script args*/
  unsigned char script[SCRIPT_SIZE];
  unsigned char hash[HASH_SIZE];
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

  /* loop transaction */

  size_t index = 0;
  while (1)
  {
    ret = ckb_load_cell_by_field(hash, &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);

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

    /* check input type_id equals lock_args */
    if ((len == args_bytes_seg.size) &&
        (memcmp(args_bytes_seg.ptr, hash, HASH_SIZE) == 0))
    {
      return CKB_SUCCESS;
    }

    index += 1;
  }

  return -104;
}