#include "ckb_syscalls.h"
#include "keccak256.h"
#include "protocol.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

/*
 * Verify secp256k1 signature, check the kecack256 hash of pubkey recovered from
 * signature is equal with the lock script arg.
 *
 * Arguments:
 * message,  the calculated hash of ckb transaciton.
 * lock_bytes, the signature from transcation witness.
 * lock_args, the args of lock script.
 *
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

int get_signature_from_trancation(uint64_t *chain_id, unsigned char *message,
                                  unsigned char *lock_bytes) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
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

  if (lock_bytes_seg.size < SIGNATURE_SIZE ||
      lock_bytes_seg.size > SIGNATURE_SIZE + 1) {
    return ERROR_ARGUMENTS_LEN;
  }

  if (lock_bytes_seg.size == SIGNATURE_SIZE) {
    *chain_id = 1;
    memcpy(lock_bytes, lock_bytes_seg.ptr, SIGNATURE_SIZE);
  } else {
    memcpy(chain_id, lock_bytes_seg.ptr, 1);
    memcpy(lock_bytes, (lock_bytes_seg.ptr + 1), SIGNATURE_SIZE);
    // return *chain_id;
  }

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  keccak_update(&sha3_ctx, (unsigned char *)&witness_len, sizeof(uint64_t));
  keccak_update(&sha3_ctx, temp, witness_len);

  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    keccak_update(&sha3_ctx, (unsigned char *)&len, sizeof(uint64_t));
    keccak_update(&sha3_ctx, temp, len);
    i += 1;
  }
  /* Digest witnesses that not covered by inputs */
  i = calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    keccak_update(&sha3_ctx, (unsigned char *)&len, sizeof(uint64_t));
    keccak_update(&sha3_ctx, temp, len);

    i += 1;
  }
  keccak_final(&sha3_ctx, message);
  return CKB_SUCCESS;
}