/**
 *  This file provide 2 API:
 *  1. secp256k1 verification
 *  2. message digest calacation and chain_id/siganture extraction
 *
 */
#ifndef PWLOCK_HELPER_H
#define PWLOCK_HELPER_H

#include "ckb_syscalls.h"
#include "keccak256.h"
#include "protocol.h"
#include "ripemd160.h"
#include "secp256k1_helper.h"
#include "sha256.h"

// #define SHA256_CTX sha256_context
#define HASH_SIZE 32
#define BLAKE160_SIZE 20
#define RIPEMD160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key
#define SHA256_SIZE 32
#define TEMP_SIZE 32768
#define RECID_INDEX 64
#define COMPRESSED_PUBKEY_SIZE 33
#define NONE_COMPRESSED_PUBKEY_SIZE 65

/**
 * Verify secp256k1 signature, check the kecack256 hash of pubkey recovered from
 * signature is equal with the lock script arg.
 *
 * @param message  the calculated hash of ckb transaciton.
 * @param lock_bytes the signature from transcation witness.
 * @param lock_args the args of lock script.
 *
 */
int verify_signature(unsigned char *message, unsigned char *lock_bytes,
                     const void *lock_args) {
  unsigned char temp[TEMP_SIZE];

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  int ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_UNCOMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &temp[1], pubkey_size - 1);
  keccak_final(&sha3_ctx, temp);

  if (memcmp(lock_args, &temp[12], BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return CKB_SUCCESS;
}

/**
 * Verify secp256k1 signature, check the kecack256 hash of pubkey (compressed or
 * uncompressed) recovered from signature is equal with the lock script arg.
 *
 * @param message  the calculated hash of ckb transaciton.
 * @param lock_bytes the signature from transcation witness.
 * @param lock_args the args of lock script.
 *
 */
int verify_signature_btc(unsigned char *message, unsigned char *lock_bytes,
                         const void *lock_args) {
  unsigned char temp[TEMP_SIZE];

  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  int ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  int recid = (lock_bytes[0] - 27) & 3;
  bool fComp = ((lock_bytes[0] - 27) & 4) != 0;

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, &lock_bytes[1], recid) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* serialize pubkey */
  size_t pubkey_size =
      fComp ? COMPRESSED_PUBKEY_SIZE : NONE_COMPRESSED_PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(
          &context, temp, &pubkey_size, &pubkey,
          fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  SHA256_CTX sha256_ctx;
  /* check pubkey hash */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, temp, pubkey_size);
  sha256_final(&sha256_ctx, temp);

  ripemd160_state ripe160_ctx;
  ripemd160_init(&ripe160_ctx);
  ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
  ripemd160_finalize(&ripe160_ctx, temp);
  if (memcmp(lock_args, temp, RIPEMD160_SIZE) != 0) {
    return ERROR_PUBKEY_RIPEMD160_HASH;
  }

  return CKB_SUCCESS;
}

const char HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void bin_to_hex(unsigned char *source, unsigned char *dest, size_t len) {
  for (int i = 0; i < len; i++) {
    dest[i * 2] = HEX_TABLE[source[i] >> 4];
    dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
  }
  return;
}

#endif