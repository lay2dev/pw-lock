/* The file perform signature verification from Ethereum/EOS/Tron signed by
 * wallet  */
#include "common.h"
#include "libsig.h"
#include "secp256k1_keccak256_helper.h"
#include "secp256k1_keccak256_lock_eos.h"
#include "secp256k1_keccak256_lock_eth.h"
#include "secp256k1_keccak256_lock_tron.h"

/**
 * verify transaction signature signed by wallets.
 * get wallet type by first byte of witness.lock
 * 1 = Ethereum 2 = EOS  3 = TRON
 *
 * @param eth_address keccak256 hash of pubkey last 20 bytes, used to shield the
 * real pubkey.
 *
 */
int verify_secp256k1_keccak_sighash_all(unsigned char* eth_address) {
  int ret;
  unsigned char message[HASH_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  uint64_t chain_id;

  ret = get_signature_from_trancation(&chain_id, message, lock_bytes);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (chain_id == 1) {
    return verify_secp256k1_keccak_eth_sighash_all(message, eth_address,
                                                   lock_bytes);
  } else if (chain_id == 2) {
    return verify_secp256k1_keccak_eos_sighash_all(message, eth_address,
                                                   lock_bytes);
  } else if (chain_id == 3) {
    return verify_secp256k1_keccak_tron_sighash_all(message, eth_address,
                                                    lock_bytes);
  } else {
    return -101;
  }
}
