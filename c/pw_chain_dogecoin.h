#include "ckb_syscalls.h"
#include "common.h"
#include "pw_k1_helper.h"
#include "secp256k1_helper.h"
#include "sha256.h"

#define u8 unsigned char
#define MESSAGE_HEX_LEN 64

const char DOGE_MESSAGE_MAGIC[26] = "Dogecoin Signed Message:\n";
const int8_t DOGE_MAGIC_LEN = 25;

/**
 * @param message transaction message digest for signature verification, size is
 * 32 bytes
 * @param doge_address last 20 bytes ripemd160(sha256) hash of pubkey, used to
 * shield the real pubkey. size is 20 bytes
 * @param lock_bytes signature signed by Doge wallet, size is 65 bytes.
 *
 */
int validate_dogecoin(unsigned char* message, unsigned char* doge_address,
                      unsigned char* lock_bytes) {
  u8 temp[MESSAGE_HEX_LEN];

  bin_to_hex(message, temp, 32);

  SHA256_CTX sha256_ctx;
  // len of magic + magic string + len of message, size is 27 Byte
  u8 MESSAGE_MAGIC[DOGE_MAGIC_LEN + 2];
  MESSAGE_MAGIC[0] = DOGE_MAGIC_LEN;  // MESSAGE_MAGIC length
  memcpy(&MESSAGE_MAGIC[1], DOGE_MESSAGE_MAGIC, DOGE_MAGIC_LEN);
  MESSAGE_MAGIC[26] = MESSAGE_HEX_LEN;  // message length

  /* Calculate signature message */
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, MESSAGE_MAGIC, DOGE_MAGIC_LEN + 2);
  sha256_update(&sha256_ctx, temp, MESSAGE_HEX_LEN);
  sha256_final(&sha256_ctx, message);

  //doble hash
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, message, SHA256_SIZE);
  sha256_final(&sha256_ctx, message);

  return verify_signature_btc(message, lock_bytes, doge_address);
}
