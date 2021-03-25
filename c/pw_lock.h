/* The file perform signature verification from Ethereum/EOS/Tron signed by
 * wallet  */
#include "blake2b.h"
#include "common.h"
#include "pw_chain_bitcoin.h"
#include "pw_chain_dogecoin.h"
#include "pw_chain_eos.h"
#include "pw_chain_ethereum.h"
#include "pw_chain_extended.h"
#include "pw_chain_tron.h"
#include "pw_k1_helper.h"

/* 32 KB */
#define MIN_SIGNATURE_SIZE 65
#define SCRIPT_SIZE 32768
#define MAX_WITNESS_SIZE 32768
#define MAX_LOCK_ARGS_SIZE 1024

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

/**
 * extract chain id and signature from witness.lock, and calculate tx message
 * digest with blake2b hash algorithm
 *
 * @param chain_id wallet type, 1 = Ethereum 2 = EOS 3 = TRON
 * @param message message digest of transaction
 * @param lock_bytes signature
 * @param lock_bytes_size the size of signature
 *
 */
int get_signature_from_trancation(uint64_t *chain_id, unsigned char *message,
                                  unsigned char *lock_bytes,
                                  uint64_t *lock_bytes_size) {
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

  if (lock_bytes_seg.size < MIN_SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  /* in order to compatible with old version pw-lock which has no chain id*/
  if (lock_bytes_seg.size == MIN_SIGNATURE_SIZE) {
    *chain_id = 1;
    memcpy(lock_bytes, lock_bytes_seg.ptr, MIN_SIGNATURE_SIZE);
    *lock_bytes_size = MIN_SIGNATURE_SIZE;
  } else {
    memcpy(chain_id, lock_bytes_seg.ptr, 1);
    memcpy(lock_bytes, (lock_bytes_seg.ptr + 1), lock_bytes_seg.size - 1);
    *lock_bytes_size = lock_bytes_seg.size - 1;
  }

  /* Load tx hash */
  unsigned char tx_hash[HASH_SIZE];
  len = HASH_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, HASH_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, HASH_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (unsigned char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

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
    blake2b_update(&blake2b_ctx, (unsigned char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
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
    blake2b_update(&blake2b_ctx, (unsigned char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);

    i += 1;
  }

  blake2b_final(&blake2b_ctx, message, HASH_SIZE);
  return CKB_SUCCESS;
}

int read_pw_args(unsigned char *lock_args, uint64_t *lock_args_size) {
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
  if (args_bytes_seg.size < BLAKE160_SIZE ||
      args_bytes_seg.size > MAX_LOCK_ARGS_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  memcpy(lock_args, args_bytes_seg.ptr, args_bytes_seg.size);
  *lock_args_size = args_bytes_seg.size;

  return CKB_SUCCESS;
}

/**
 * Verify transaction signature signed by wallets.
 * get wallet type by first byte of witness.lock.
 * 1 = Ethereum, 2 = EOS, 3 = TRON, 4 = BTC
 *
 * Besides: we use the same way as ethereum address to generate lock script args
 * for Ethereum/EOS/TRON. lock.args = keccak256(pubkey).slice(-20)
 * for BTC lock.args = ripemd160(sha256(pubkey))
 * @param code_buf code buffer for dynamic load library from cell deps
 * @param code_buf_size the size of code buffer
 *
 */
int verify_pwlock_sighash_all(uint8_t *code_buf, uint64_t code_buf_size) {
  int ret;
  unsigned char message[HASH_SIZE];
  unsigned char lock_args[MAX_LOCK_ARGS_SIZE];
  unsigned char lock_bytes[TEMP_SIZE];
  uint64_t chain_id = 1;
  uint64_t lock_args_size = 0;
  uint64_t lock_bytes_size = 0;

  ret = read_pw_args(lock_args, &lock_args_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  ret = get_signature_from_trancation(&chain_id, message, lock_bytes,
                                      &lock_bytes_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

#ifdef HAS_ETHEREUM
  if (chain_id == 1) {
    return validate_ethereum(message, lock_args, lock_args_size, lock_bytes,
                             lock_bytes_size);
  }
#endif

#ifdef HAS_EOS
  if (chain_id == 2) {
    return validate_eos(message, lock_args, lock_args_size, lock_bytes,
                        lock_bytes_size);
  }
#endif

#ifdef HAS_TRON
  if (chain_id == 3) {
    return validate_tron(message, lock_args, lock_args_size, lock_bytes,
                         lock_bytes_size);
  }
#endif

#ifdef HAS_BITCOIN
  if (chain_id == 4) {
    return validate_bitcoin(message, lock_args, lock_args_size, lock_bytes,
                            lock_bytes_size);
  }
#endif

#ifdef HAS_DOGECOIN
  if (chain_id == 5) {
    return validate_dogecoin(message, lock_args, lock_args_size, lock_bytes,
                             lock_bytes_size);
  }
#endif

#ifdef HAS_EXTENDED_VALIDATOR
  if (chain_id == 0xFF) {
    return validate_extended(message, lock_args, lock_args_size, lock_bytes,
                             lock_bytes_size, code_buf, code_buf_size);
  }
#endif
  return -101;
}
