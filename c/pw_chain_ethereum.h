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
 * Since not all ethereum wallets support EIP712, the verification will support
 * two hashes for transaction, both of them are ok.
 * 1. ethereum peronsal hash
 * 2. EIP712 typed data hash
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
                      unsigned char *lock_bytes, uint64_t lock_bytes_size) {
  if (lock_bytes_size != ETHEREUM_SIGNATURE_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

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

  return ret;
}
