

#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "ripemd160.h"
#include "secp256k1_helper.h"
#include "sha256.h"

#define BLAKE2B_BLOCK_SIZE 32
#define RIPEMD160_SIZE 20
#define SHA256_SIZE 32
#define TEMP_SIZE 1024
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define RECOVERABLE_SIGNATURE_SIZE 65
#define NONE_RECOVERABLE_SIGNATURE_SIZE 64
#define COMPRESSED_PUBKEY_SIZE 33
#define NONE_COMPRESSED_PUBKEY_SIZE 65
/* RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE */
#define MAX_LOCK_SIZE 130

// without pubkey in witness
int verify_secp256k1_ripemd160_sha256_sighash_all_without_pubkey(
    const void *lock_args, unsigned char *witness, uint64_t wit_len,
    mol_seg_t lock_bytes_seg) {
  int ret;
  uint64_t len = 0;
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  unsigned char temp[TEMP_SIZE];
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];

  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  // copy signature
  unsigned char lock_bytes[RECOVERABLE_SIGNATURE_SIZE];
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  secp256k1_context context;
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  unsigned char message[SHA256_SIZE];
  sha256_state sha256_ctx;

  len = wit_len;
  /* Calculate signature message */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);

  sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
  sha256_update(&sha256_ctx, witness, len);

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
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
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
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
    i += 1;
  }
  sha256_finalize(&sha256_ctx, message);

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

  /* try uncompressed key first */
  /* serialize pubkey */
  size_t pubkey_size = COMPRESSED_PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  /* check pubkey hash */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, temp, pubkey_size);
  sha256_finalize(&sha256_ctx, temp);

  ripemd160_state ripe160_ctx;
  ripemd160_init(&ripe160_ctx);
  ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
  ripemd160_finalize(&ripe160_ctx, temp);
  if (memcmp(lock_args, temp, RIPEMD160_SIZE) != 0) {
    /* try compressed pubkey */
    /* serialize pubkey */
    size_t pubkey_size = NONE_COMPRESSED_PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED) != 1) {
      return ERROR_SECP_SERIALIZE_PUBKEY;
    }

    /* check pubkey hash */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, temp, pubkey_size);
    sha256_finalize(&sha256_ctx, temp);

    ripemd160_state ripe160_ctx;
    ripemd160_init(&ripe160_ctx);
    ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
    ripemd160_finalize(&ripe160_ctx, temp);
    if (memcmp(lock_args, temp, RIPEMD160_SIZE) != 0) {
      return ERROR_PUBKEY_RIPEMD160_HASH;
    }
  }

  return 0;
}

// witness include pubkey
int verify_secp256k1_ripemd160_sha256_sighash_all_with_pubkey(
    const void *lock_args, unsigned char *witness, uint64_t wit_len,
    mol_seg_t lock_bytes_seg) {
  int ret;
  uint64_t len = 0;
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  unsigned char temp[TEMP_SIZE];
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];

  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  uint64_t lock_len = lock_bytes_seg.size;

  secp256k1_context context;
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_signature signature;
  if (secp256k1_ecdsa_signature_parse_compact(&context, &signature,
                                              lock_bytes_seg.ptr) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* parse pubkey */
  secp256k1_pubkey pubkey;
  uint64_t signature_len;
  if (lock_len == RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE ||
      lock_len ==
          NONE_RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE) {
    signature_len = lock_len - NONE_COMPRESSED_PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_parse(&context, &pubkey,
                                  lock_bytes_seg.ptr + signature_len,
                                  NONE_COMPRESSED_PUBKEY_SIZE) == 0) {
      return ERROR_SECP_PARSE_PUBKEY;
    }
  } else {
    signature_len = lock_len - COMPRESSED_PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_parse(&context, &pubkey,
                                  lock_bytes_seg.ptr + signature_len,
                                  COMPRESSED_PUBKEY_SIZE) == 0) {
      return ERROR_SECP_PARSE_PUBKEY;
    }
  }

  /* check pubkey hash */
  sha256_state sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, lock_bytes_seg.ptr + signature_len,
                lock_len - signature_len);
  sha256_finalize(&sha256_ctx, temp);

  ripemd160_state ripe160_ctx;
  ripemd160_init(&ripe160_ctx);
  ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
  ripemd160_finalize(&ripe160_ctx, temp);
  if (memcmp(lock_args, temp, RIPEMD160_SIZE) != 0) {
    return ERROR_PUBKEY_RIPEMD160_HASH;
  }

  len = wit_len;
  /* Calculate signature message */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
  /* Clear lock field signature to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, signature_len);
  sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
  sha256_update(&sha256_ctx, witness, len);

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
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
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
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
    i += 1;
  }

  sha256_finalize(&sha256_ctx, temp);

  /* verify signature */
  if (secp256k1_ecdsa_verify(&context, &signature, temp, &pubkey) != 1) {
    return ERROR_SECP_VERIFICATION;
  }

  return 0;
}

int verify_secp256k1_ripemd160_sha256_sighash_all(
    unsigned char btc_address[RIPEMD160_SIZE]) {
  int ret;
  uint64_t len = 0;
  unsigned char witness[MAX_WITNESS_SIZE];

  /* Now we load actual witness data using the same input index above. */
  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(witness, len, &lock_bytes_seg);
  if (ret != CKB_SUCCESS) {
    return ERROR_ENCODING;
  }

  uint64_t lock_len = lock_bytes_seg.size;
  if (lock_len != RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE &&
      lock_len != RECOVERABLE_SIGNATURE_SIZE + COMPRESSED_PUBKEY_SIZE &&
      lock_len !=
          NONE_RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE &&
      lock_len != NONE_RECOVERABLE_SIGNATURE_SIZE + COMPRESSED_PUBKEY_SIZE &&
      lock_len != RECOVERABLE_SIGNATURE_SIZE) {
    return ERROR_WITNESS_SIZE;
  }
  // recover pubkey, input witness to decrease calls of ckb_load_witness
  if (lock_len == RECOVERABLE_SIGNATURE_SIZE) {
    return verify_secp256k1_ripemd160_sha256_sighash_all_without_pubkey(
        btc_address, witness, len, lock_bytes_seg);
  }

  // verify pubkey
  return verify_secp256k1_ripemd160_sha256_sighash_all_with_pubkey(
      btc_address, witness, len, lock_bytes_seg);
}