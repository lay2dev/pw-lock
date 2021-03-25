/**
 * The file perform signature verification from extended validator which follows
 * the protocol
 * https://talk.nervos.org/t/rfc-swappable-signature-verification-protocol-spec/4802
 *
 */
#include "ckb_swappable_signatures.h"
#include "common.h"

#define HASH_SIZE 32
#define MAX_CODE_SIZE (1024 * 1024)

/**
 * Verify the signature from extended validator. dynamic loading validator from
 * cell deps, then perform common func validate_siganture()
 *
 * @param message the transaction digest message with blake2b hash algorithm,
 * size if 32 bytes
 * @param lock_args script lock args
 * @param lock_args_size size of script lock args
 * @param lock_bytes  a signature in witness.lock field used to present
 * ownership.
 * @param lock_bytes_size size of lock bytes
 *
 */
int validate_extended(unsigned char *message, unsigned char *lock_args,
                      uint64_t lock_args_size, unsigned char *lock_bytes,
                      uint64_t lock_bytes_size, uint8_t *code_buffer,
                      uint64_t code_buffer_size) {
  int ret;
  if (lock_args_size < 34) {
    return ERROR_ARGUMENTS_LEN;
  }

  CkbSwappableSignatureInstance instance;
  instance.code_buffer = code_buffer;
  instance.code_buffer_size = code_buffer_size;

  /* parse args */
  uint8_t extended_code_hash[HASH_SIZE];
  uint8_t hash_type = 1;
  uint8_t identify_size = 0;
  uint8_t *identity;

  memcpy(extended_code_hash, lock_args, HASH_SIZE);
  memcpy(&hash_type, lock_args + HASH_SIZE, 1);
  memcpy(&identify_size, lock_args + HASH_SIZE + 1, 1);
  identity = lock_args + HASH_SIZE + 2;

  /* dynamice load extended validator */
  ret = ckb_initialize_swappable_signature(extended_code_hash, hash_type,
                                           &instance);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* perform validation */
  size_t sig_len = 1 + identify_size + lock_bytes_size;
  uint8_t sig_buf[sig_len];
  size_t output_len = 0;
  uint8_t output[HASH_SIZE];

  memcpy(sig_buf, &identify_size, 1);
  if (identify_size > 0) {
    memcpy(sig_buf + 1, identity, identify_size);
  }
  memcpy(sig_buf + identify_size + 1, lock_bytes, lock_bytes_size);

  ret = (&instance)->verify_func(NULL, sig_buf, sig_len, message, HASH_SIZE,
                                 output, &output_len);

  if (ret != CKB_SUCCESS) {
    return ret;
  }

  return CKB_SUCCESS;
}
