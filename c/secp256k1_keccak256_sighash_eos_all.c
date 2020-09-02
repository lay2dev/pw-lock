 /* The script perform secp256k1_keccak256_sighash_all verification. */
#include "ckb_syscalls.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "libsig.h"
#include "secp256k1_keccak256_helper.h"

#define SHA256_CTX sha256_context
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

 int split_hex_hash(unsigned char* source, unsigned char* dest) {
     int i;
     for (i = 0; i < BLAKE2B_BLOCK_SIZE; i++) {
         if(i > 0 && i % 6 == 0){
             *dest = ' ';
             dest++;
         }
         dest += sprintf((char *)dest, "%02x", source[i]);
     }
     return 0;
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
  if (args_bytes_seg.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }


  unsigned char message[BLAKE2B_BLOCK_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];

  ret = get_signature_from_trancation(message, lock_bytes);
  if(ret != CKB_SUCCESS){
    return ret;
  }

  /* split message to words length <= 12 */

  int split_message_len = BLAKE2B_BLOCK_SIZE * 2 + 5;
  unsigned char splited_message[split_message_len];
  split_hex_hash(message, splited_message);

  SHA256_CTX sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, splited_message, split_message_len);
  sha256_final(&sha256_ctx, message);

  return verify_signature(message, lock_bytes, args_bytes_seg.ptr);

}