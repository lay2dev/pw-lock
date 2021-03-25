/**
 * The file perform ethereum wallet signature verification.
 * Both of the below two signatures are suppported.
 *    1. web3.eth.personalSign
 *    2. web3.eth.signTypedData_v4
 *
 */

#include "pw_k1_helper.h"

#define ETHEREUM_SIGNATURE_SIZE 65

/**
 * Verify the transaction using secp256k1 as sig algorithm and keccak256 as hash
 * algorithm.
 *
 * the verification will support ethereum peronsal sign
 *
 * @param message the transaction digest message with keccak256 hash algorithm,
 * size if 32 bytes
 * @param eth_address last 20 bytes keccak256 hash of pubkey, used to shield the
 * real pubkey. size is 20 bytes
 * @param lock_bytes  a signature in witness.lock field used to present
 * ownership. size is 65 bytes
 *
 */
int validate_ethereum(unsigned char *message, unsigned char *eth_address,
                      uint64_t lock_args_size, unsigned char *lock_bytes,
                      uint64_t lock_bytes_size) {
  if (lock_bytes_size != ETHEREUM_SIGNATURE_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  int ret;

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
  unsigned char eth_prefix[28];
  eth_prefix[0] = 0x19;
  memcpy(eth_prefix + 1, "Ethereum Signed Message:\n32", 27);

  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  /* verify signature with peronsal hash */
  ret = verify_signature(message, lock_bytes, eth_address);
  if (ret == CKB_SUCCESS) {
    return CKB_SUCCESS;
  }

  return ret;
}
