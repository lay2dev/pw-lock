#include "ckb_syscalls.h"
#include "common.h"
#include "libsig.h"
#include "ripemd160.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define RIPEMD160_SIZE 20
#define SHA256_SIZE 32
// #define TEMP_LEN 1024
#define RECID_INDEX 64

#define RECOVERABLE_SIGNATURE_SIZE 65
#define NONE_RECOVERABLE_SIGNATURE_SIZE 64
#define COMPRESSED_PUBKEY_SIZE 33
#define NONE_COMPRESSED_PUBKEY_SIZE 65
/* RECOVERABLE_SIGNATURE_SIZE + NONE_COMPRESSED_PUBKEY_SIZE */

const char BTC_MESSAGE_MAGIC[25] = "Bitcoin Signed Message:\n";
const char DOGE_MESSAGE_MAGIC[26] = "Dogecoin Signed Message:\n";
const char HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

void bin_to_hex(unsigned char* source, unsigned char* dest, size_t len) {
  for (int i = 0; i < len; i++) {
    dest[i * 2] = HEX_TABLE[source[i] >> 4];
    dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
  }
  return;
}

// without pubkey in witness
int verify_secp256k1_ripemd160_sha256_btc_sighash_all(
    unsigned char* message, unsigned char* btc_address,
    unsigned char* lock_bytes, u8 is_btc) {
  int ret;
  unsigned char temp[TEMP_SIZE];
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];

  bin_to_hex(message, temp, 32);

  sha256_context sha256_ctx;
  if (is_btc == 0) {
    u8 MESSAGE_MAGIC[26];
    MESSAGE_MAGIC[0] = 24;  // MESSAGE_MAGIC length
    memcpy(&MESSAGE_MAGIC[1], BTC_MESSAGE_MAGIC, 24);
    MESSAGE_MAGIC[25] = 64;  // message length

    /* Calculate signature message */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, MESSAGE_MAGIC, 26);
    sha256_update(&sha256_ctx, temp, 64);
    sha256_final(&sha256_ctx, message);

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, message, 32);
    sha256_final(&sha256_ctx, message);
  } else if (is_btc == 1) {
    u8 MESSAGE_MAGIC[27];
    MESSAGE_MAGIC[0] = 25;  // MESSAGE_MAGIC length
    memcpy(&MESSAGE_MAGIC[1], DOGE_MESSAGE_MAGIC, 25);
    MESSAGE_MAGIC[26] = 64;  // message length

    /* Calculate signature message */
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, MESSAGE_MAGIC, 27);
    sha256_update(&sha256_ctx, temp, 64);
    sha256_final(&sha256_ctx, message);

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, message, 32);
    sha256_final(&sha256_ctx, message);
  } else {
    return -102;
  }
  
  secp256k1_context context;
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
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

  /* check pubkey hash */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, temp, pubkey_size);
  sha256_final(&sha256_ctx, temp);

  ripemd160_state ripe160_ctx;
  ripemd160_init(&ripe160_ctx);
  ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
  ripemd160_finalize(&ripe160_ctx, temp);
  if (memcmp(btc_address, temp, RIPEMD160_SIZE) != 0) {
    return ERROR_PUBKEY_RIPEMD160_HASH;
  }

  return 0;
}
