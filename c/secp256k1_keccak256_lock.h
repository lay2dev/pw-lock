#include "common.h"
#include "libsig.h"
#include "secp256k1_keccak256_helper.h"
#include "secp256k1_keccak256_lock_eth.h"
#include "secp256k1_keccak256_lock_eos.h"
#include "secp256k1_keccak256_lock_tron.h"


#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key 
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif


int verify_secp256k1_keccak_sighash_all(unsigned char* eth_address) {
  int ret;
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  uint64_t chain_id;

  ret = get_signature_from_trancation(&chain_id, message, lock_bytes);
  if(ret != CKB_SUCCESS){
    return ret;
  }

  if(chain_id == 1){
    return verify_secp256k1_keccak_eth_sighash_all(message, eth_address, lock_bytes);
  }else if(chain_id == 2){
    return verify_secp256k1_keccak_eos_sighash_all(message, eth_address, lock_bytes);
  }else if(chain_id == 3){
    return verify_secp256k1_keccak_tron_sighash_all(message, eth_address, lock_bytes);
  }else{
    return -101;
  }
}
