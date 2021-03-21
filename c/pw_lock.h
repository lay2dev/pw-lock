/* The file perform signature verification from Ethereum/EOS/Tron signed by
 * wallet  */
#include "common.h"
#include "pw_chain_btcoin.h"
#include "pw_chain_dogecoin.h"
#include "pw_chain_eos.h"
#include "pw_chain_ethereum.h"
#include "pw_chain_tron.h"
#include "pw_k1_helper.h"

/**
 * Verify transaction signature signed by wallets.
 * get wallet type by first byte of witness.lock.
 * 1 = Ethereum, 2 = EOS, 3 = TRON, 4 = BTC
 *
 * Besides: we use the same way as ethereum address to generate lock script args
 * for Ethereum/EOS/TRON. lock.args = keccak256(pubkey).slice(-20)
 * for BTC lock.args = ripemd160(sha256(pubkey))
 * @param lock_args last 20-bytes keccak256 hash of pubkey, used to shield the
 * real pubkey. size is 20 bytes
 *
 */
int verify_pwlock_sighash_all(unsigned char* lock_args) {
  int ret;
  unsigned char message[HASH_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  uint64_t chain_id;

  ret = get_signature_from_trancation(&chain_id, message, lock_bytes);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (chain_id == 1) {
    return validate_ethereum(message, lock_args, lock_bytes);
  } else if (chain_id == 2) {
    return validate_eos(message, lock_args, lock_bytes);
  } else if (chain_id == 3) {
    return validate_tron(message, lock_args, lock_bytes);
  } else if (chain_id == 4) {
    return validate_btcoin(message, lock_args, lock_bytes);
  } else if (chain_id == 5) {
    return validate_dogecoin(message, lock_args, lock_bytes);
  } else {
    return -101;
  }
}
