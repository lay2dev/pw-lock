/**
 * This script provide a library for other ckb cell script to call. it
 * follows the protocol
 * https://talk.nervos.org/t/rfc-swappable-signature-verification-protocol-spec/4802
 *
 * including:
 * 1. secp256r1 signature verification for Webauthn signature
 */
#include "pw_webauthn.h"

__attribute__((visibility("default"))) int load_prefilled_data(void *data,
                                                               size_t *len) {
  return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int validate_signature(
    void *prefilled_data, const uint8_t *sig_buf, size_t sig_len,
    const uint8_t *msg_buf, size_t msg_len, uint8_t *output,
    size_t *output_len) {
  if (sig_len != 1 + LOCK_ARGS_SIZE + R1_WITNESS_LOCK_SIZE) {
    return ERROR_SIG_BUFFER_SIZE;
  }

  if (msg_len != HASH_SIZE) {
    return ERROR_MESSAGE_SIZE;
  }

  unsigned char pubkey_hash[LOCK_ARGS_SIZE];
  unsigned char lock_bytes[R1_WITNESS_LOCK_SIZE];

  memcpy(pubkey_hash, sig_buf + 1, LOCK_ARGS_SIZE);
  memcpy(lock_bytes, sig_buf + 1 + LOCK_ARGS_SIZE, R1_WITNESS_LOCK_SIZE);
  return validate_webauthn((unsigned char *)msg_buf, pubkey_hash, lock_bytes,
                           R1_WITNESS_LOCK_SIZE);
}