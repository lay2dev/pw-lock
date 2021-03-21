#include "ckb_syscalls.h"
#include "common.h"
#include "libsig.h"
#include "pw_k1_helper.h"
#include "secp256k1_helper.h"

#define u8 unsigned char
#define MESSAGE_HEX_LEN 64
#define BITCOIN_SIGNATURE_SIZE 65

const char BTC_MESSAGE_MAGIC[25] = "Bitcoin Signed Message:\n";
const int8_t BTC_MAGIC_LEN = 24;

/**
 * @param message transaction message digest for signature verification, size is
 * 32 bytes
 * @param btc_address last 20 bytes ripemd160(sha256) hash of pubkey, used to
 * shield the real pubkey. size is 20 bytes
 * @param lock_bytes signature signed by BTC wallet, size is 65 bytes.
 *
 */
int validate_bitcoin(unsigned char* message, unsigned char* btc_address,
                     unsigned char* lock_bytes, uint64_t lock_bytes_size) {
  if (lock_bytes_size != BITCOIN_SIGNATURE_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  u8 temp[MESSAGE_HEX_LEN];

  bin_to_hex(message, temp, 32);

  SHA256_CTX sha256_ctx;

  // len of magic + magic string + len of message, size is 26 Byte
  u8 MESSAGE_MAGIC[BTC_MAGIC_LEN + 2];
  MESSAGE_MAGIC[0] = BTC_MAGIC_LEN;  // MESSAGE_MAGIC length
  memcpy(&MESSAGE_MAGIC[1], BTC_MESSAGE_MAGIC, BTC_MAGIC_LEN);
  MESSAGE_MAGIC[25] = MESSAGE_HEX_LEN;  // message length

  /* Calculate signature message */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, MESSAGE_MAGIC, BTC_MAGIC_LEN + 2);
  sha256_update(&sha256_ctx, temp, MESSAGE_HEX_LEN);
  sha256_final(&sha256_ctx, message);

  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, message, SHA256_SIZE);
  sha256_final(&sha256_ctx, message);

  return verify_signature_btc(message, lock_bytes, btc_address);
}
