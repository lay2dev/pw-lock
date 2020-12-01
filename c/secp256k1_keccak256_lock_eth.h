/**
 * The file perform ethereum wallet signature verification.
 * Both of the below two signatures are suppported.
 *    1. web3.eth.personalSign
 *    2. web3.eth.signTypedData_v4
 *
 */
#include "bech32.h"
#define CKB_ADDRESS_PREFIX "ckb"
#define ENABLE_EIP712 false

/**
 * Format CKB address by lock script, and get the keccak256 hash of CKB address.
 *
 * @param script_seg lock script segment
 * @param hash the returned hash of ckb address
 *
 */
int hash_address(mol_seg_t *script_seg, unsigned char *hash) {
  mol_seg_t args_seg = MolReader_Script_get_args(script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(script_seg);

  /* the type id of secp256k1_blake160_signhash_all:
   * 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8 */
  unsigned char SECP256K1_BLAKE160_SIGHASH_ALL_TYPE_HASH[32] = {
      0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2,
      0x18, 0x8b, 0x23, 0xf1, 0xb9, 0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65,
      0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8};
  /* the type id of secp256k1_blake160_multisig_all:
   * 0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8 */
  unsigned char SECP256K1_BLAKE160_MULTISIG_ALL_TYPE_HASH[32] = {
      0x5c, 0x50, 0x69, 0xeb, 0x08, 0x57, 0xef, 0xc6, 0x5e, 0x1b, 0xca,
      0x0c, 0x07, 0xdf, 0x34, 0xc3, 0x16, 0x63, 0xb3, 0x62, 0x2f, 0xd3,
      0x87, 0x6c, 0x87, 0x63, 0x20, 0xfc, 0x96, 0x34, 0xe2, 0xa8};

  size_t payload_len = 0;
  size_t data_len = 0;
  unsigned char payload[1024];
  unsigned char ckb_address[1024];
  unsigned char data[1024];

  unsigned char formated_ckb_address[17];
  int ret = 0;

  if (code_hash_seg.size == 0) {
    /* empty lock script, consider address is unknow */
    data_len = 7;
    memcpy(ckb_address, "unknown", 7);
  } else {
    if (memcmp(code_hash_seg.ptr, SECP256K1_BLAKE160_SIGHASH_ALL_TYPE_HASH,
               code_hash_seg.size) == 0) {
      /* generate short ckb address */
      payload[payload_len++] = 0x01;
      payload[payload_len++] = 0x00;
    } else if (memcmp(code_hash_seg.ptr,
                      SECP256K1_BLAKE160_MULTISIG_ALL_TYPE_HASH,
                      code_hash_seg.size) == 0) {
      /* generate short ckb address */
      payload[payload_len++] = 0x01;
      payload[payload_len++] = 0x01;
    } else {
      if (*hash_type_seg.ptr == 0x01) {
        payload[payload_len++] = 0x04;
      } else {
        payload[payload_len++] = 0x02;
      }
      memcpy((void *)(payload + payload_len), code_hash_seg.ptr,
             code_hash_seg.size);
      payload_len += code_hash_seg.size;
    }
    memcpy(payload + payload_len, args_bytes_seg.ptr, args_bytes_seg.size);
    payload_len += args_bytes_seg.size;

    /* generate ckb address using bech32 lib */
    ret = convert_bits(data, &data_len, 5, payload, payload_len, 8, 1);
    if (ret == 0) return -10;
    ret =
        bech32_encode((char *)&ckb_address, CKB_ADDRESS_PREFIX, data, data_len);
    if (ret == 0) return -11;
    data_len += 10;

    /* shorten ckb address to 17 characters, using ... to substitute the middle
     * characters */
    if (data_len <= 17) {
      memcpy(formated_ckb_address, ckb_address, data_len);
    } else {
      memcpy(formated_ckb_address, ckb_address, 7);
      memcpy(formated_ckb_address + 7, "...", 3);
      memcpy(formated_ckb_address + 10, ckb_address + (data_len - 7), 7);
      data_len = 17;
    }
  }

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, formated_ckb_address, data_len);
  keccak_final(&sha3_ctx, hash);

  return CKB_SUCCESS;
}

/**
 * Format amount to number with 8 decimals and ended with "CKB", get the
 * keccak256 hash of the amount string
 *
 * @param capacity, the capacity of the output cell
 * @param hash the returned keccak256 hash of amount string
 */
int hash_amount(uint64_t capacity, unsigned char *hash) {
  unsigned char amount[100];

  /* format capacity */
  int len = snprintf((char *)&amount, 100, "%.8fCKB", capacity / 100000000.0);

  /* calculate keccak256 hash of amount */
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, amount, len);
  keccak_final(&sha3_ctx, hash);

  return CKB_SUCCESS;
}

/**
 * Calculate the EIP712 typed data hash for a CKB transcation.
 * The format of typed data is as follows:
 * {
 *   domain: {
 *     chainId: 1,
 *     name: 'ckb.pw',
 *     verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
 *     version: '1',
 *   },
 *   message: {
 *     hash:
 * '0x545529d4464064d8394c557afb06f489e7044a63984c6113385431d93dcffa1b', fee:
 * '0.00100000CKB', 'input-sum': '100.00000000CKB', to: [
 *       {
 *         address: 'ckb1qyq...qwstnwm',
 *         amount: '100.00000000CKB',
 *       },
 *       {
 *         address: 'ckb1qft...xudxcyg',
 *         amount: '799.99800000CKB',
 *       },
 *     ],
 *   },
 *   primaryType: 'CKBTransaction',
 *   types: {
 *     EIP712Domain: [
 *       { name: 'name', type: 'string' },
 *       { name: 'version', type: 'string' },
 *       { name: 'chainId', type: 'uint256' },
 *       { name: 'verifyingContract', type: 'address' },
 *     ],
 *     CKBTransaction: [
 *       { name: 'hash', type: 'bytes32' },
 *       { name: 'fee', type: 'string' },
 *       { name: 'input-sum', type: 'string' },
 *       { name: 'to', type: 'Output[]' },
 *     ],
 *     Output: [
 *       { name: 'address', type: 'string' },
 *       { name: 'amount', type: 'string' },
 *     ],
 *   },
 * }
 *
 * @param tx_message the ethereum personal signed hash of transaction body.
 * @param type_data_hash the returned calculated typed data hash
 *
 */
int calculate_typed_data(unsigned char *tx_message,
                         unsigned char *typed_data_hash) {
  int ret;
  uint64_t len = 0;
  size_t index = 0;
  uint64_t input_capacities = 0;
  uint64_t output_capacities = 0;
  uint64_t tx_fee = 0;

  unsigned char script[SCRIPT_SIZE];
  mol_seg_t script_seg;

  /**
   *
   *  hard coded hash
   */
  /* typed data prefix */
  unsigned char TYPEDDATA_PREFIX[2] = {0x19, 0x01};
  /* hash for type CKBTransaction, is equal to
   * web3utils.sha3('CKBTransaction(bytes32 hash,string fee,string
   * input-sum,Output[] to)Output(string address,string amount)') */
  unsigned char CKBTRANSACTION_TYPEHASH[HASH_SIZE] = {
      0x17, 0xe4, 0x04, 0xd0, 0xcd, 0xcc, 0x43, 0x1e, 0xe6, 0xdf, 0x80,
      0x7a, 0xbc, 0xcc, 0x69, 0x5d, 0x95, 0xd0, 0x38, 0xf5, 0x76, 0x47,
      0xe2, 0xef, 0x92, 0xb9, 0x68, 0x66, 0xca, 0xe5, 0x9d, 0x04};
  /* hash for type Output, is equal to web3utils.sha3('Output(string
   * address,string amount)') */
  unsigned char OUTPUT_TYPEHASH[HASH_SIZE] = {
      0xef, 0xdd, 0x9a, 0xc6, 0xc9, 0x8f, 0xcb, 0xab, 0xc5, 0x2e, 0xf1,
      0xd8, 0xa4, 0xd3, 0xac, 0xcd, 0x43, 0x96, 0x36, 0x2a, 0x21, 0x1c,
      0xbf, 0x7a, 0x3c, 0x20, 0xc2, 0x89, 0x22, 0x08, 0x19, 0x13};
  /* hash for domain separator, is equal to web3utils.sha3("EIP712Domain(string
   * name,string version,uint256 chainId,address verifyingContract)") */
  unsigned char DOMAIN_SEPARATOR[HASH_SIZE] = {
      0xec, 0x9e, 0x64, 0xcb, 0x49, 0x31, 0x37, 0x85, 0x0e, 0x3d, 0x5d,
      0x47, 0x3c, 0xa1, 0x09, 0xea, 0xe1, 0x47, 0xad, 0xb8, 0xa6, 0xbf,
      0x46, 0x0b, 0xf2, 0x06, 0xe9, 0x0f, 0x62, 0x64, 0x2e, 0x3f,
  };

  unsigned char address_hash[HASH_SIZE];
  unsigned char amount_hash[HASH_SIZE];
  unsigned char message[HASH_SIZE];

  /* calculate the total input capacities of tx */
  while (1) {
    uint64_t capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY);

    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8) {
      return ERROR_SYSCALL;
    }

    if (__builtin_uaddl_overflow(input_capacities, capacity,
                                 &input_capacities)) {
      return ERROR_OVERFLOW;
    }

    index += 1;
  }

  index = 0;

  SHA3_CTX sha3_ctx, sha3_ctx_output;
  keccak_init(&sha3_ctx);

  /* calculate the total output capacities and OUTPUT hash value */
  while (1) {
    uint64_t capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                 CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);

    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      // return ret;
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8) {
      return ERROR_SYSCALL;
    }
    if (index >= MAX_OUTPUT_LENGTH) {
      return ERROR_TOO_MANY_OUTPUT_CELLS;
    }

    if (__builtin_uaddl_overflow(output_capacities, capacity,
                                 &output_capacities)) {
      return ERROR_OVERFLOW;
    }

    len = SCRIPT_SIZE;
    ret = ckb_load_cell_by_field(script, &len, 0, index, CKB_SOURCE_OUTPUT,
                                 CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > SCRIPT_SIZE) {
      return ERROR_SCRIPT_TOO_LONG;
    }
    script_seg.ptr = (uint8_t *)script;
    script_seg.size = len;

    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
      return ERROR_ENCODING;
    }

    hash_amount(capacity, amount_hash);
    ret = hash_address(&script_seg, address_hash);
    if (ret != CKB_SUCCESS) return ret;

    keccak_init(&sha3_ctx_output);
    keccak_update(&sha3_ctx_output, OUTPUT_TYPEHASH, 32);

    keccak_update(&sha3_ctx_output, address_hash, 32);
    keccak_update(&sha3_ctx_output, amount_hash, 32);

    keccak_final(&sha3_ctx_output, message);

    /* output hash */
    keccak_update(&sha3_ctx, message, 32);
    index += 1;
  }

  /*
   * Calcuate tx fee.
   * Notice: For dao withdraw transcation, the calculated fee may be negative,
   * we set the tx fee to zero. The rules for dao withdraw tx should be
   * followed, when build typed data at other places.
   */
  if (__builtin_usubl_overflow(input_capacities, output_capacities, &tx_fee)) {
    // return ERROR_OVERFLOW;
    tx_fee = 0;
  }

  /* output array hash */
  keccak_final(&sha3_ctx, message);
  /* ckb tx value hash */
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, CKBTRANSACTION_TYPEHASH, 32);
  /* hash */
  keccak_update(&sha3_ctx, tx_message, 32);
  /* fee */
  hash_amount(tx_fee, amount_hash);
  keccak_update(&sha3_ctx, amount_hash, 32);
  /* input-sum */
  hash_amount(input_capacities, amount_hash);
  keccak_update(&sha3_ctx, amount_hash, 32);
  /* to */
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  /* typed data hash */
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, TYPEDDATA_PREFIX, 2);
  keccak_update(&sha3_ctx, DOMAIN_SEPARATOR, 32);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, typed_data_hash);

  return CKB_SUCCESS;
}

/**
 * Verify the transaction using secp256k1 as sig algorithm and keccak256 as hash
 * algorithm.
 *
 * Since not all ethereum wallets support EIP712, the verification will support
 * two hashes for transaction, both of them are ok.
 * 1. ethereum peronsal hash
 * 2. EIP712 typed data hash
 *
 * @param message the transaction digest message with keccak256 hash algorithm
 * @param eth_address keccak256 hash of pubkey last 20 bytes, used to shield the
 * real pubkey.
 * @param lock_bytes  a signature in witness.lock field used to present
 * ownership.
 *
 */
int verify_secp256k1_keccak_eth_sighash_all(unsigned char *message,
                                            unsigned char *eth_address,
                                            unsigned char *lock_bytes) {
  int ret;

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
  unsigned char eth_prefix[28] = {0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65,
                                  0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e,
                                  0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73,
                                  0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32};
  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  /* verify signature with peronsal hash */
  ret = verify_signature(message, lock_bytes, eth_address);
  if (ret == CKB_SUCCESS) {
    return CKB_SUCCESS;
  }

  if (ENABLE_EIP712) {
    /* Calculate Typed Data hash */
    ret = calculate_typed_data(message, message);
    if (ret != CKB_SUCCESS) {
      return ret;
    }

    /* verify signature with typed data hash */
    ret = verify_signature(message, lock_bytes, eth_address);
  }

  return ret;
}
