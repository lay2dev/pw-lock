/* The file perform signature verification from Ethereum/EOS/Tron signed by
 * wallet  */
#include "common.h"
#include "libsig.h"
#include "secp256k1_keccak256_helper.h"
#include "secp256k1_keccak256_lock_eos.h"
#include "secp256k1_keccak256_lock_eth.h"
#include "secp256k1_keccak256_lock_tron.h"
#include "secp256k1_ripemd160_sha256_lock_btc.h"

/**
 * Verify transaction signature signed by wallets.
 * get wallet type by first byte of witness.lock.
 * 1 = Ethereum, 2 = EOS, 3 = TRON, 4 = BTC
 *
 * Besides: we use the same way as ethereum address to generate lock script args
 * for Ethereum/EOS/TRON. lock.args = keccak256(pubkey).slice(-20)
 * for BTC lock.args = ripemd160(sha256(pubkey))
 * @param eth_address last 20-bytes keccak256 hash of pubkey, used to shield the
 * real pubkey. size is 20 bytes
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
  } else if (chain_id == 4) {
    return verify_secp256k1_ripemd160_sha256_btc_sighash_all(
        message, eth_address, lock_bytes, 0);
  } else if (chain_id == 5) {
    return verify_secp256k1_ripemd160_sha256_btc_sighash_all(
        message, eth_address, lock_bytes, 1);
  } else {
    return -101;
  }
}
