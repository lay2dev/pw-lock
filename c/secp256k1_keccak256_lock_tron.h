 /* The script perform secp256k1_keccak256_sighash_all verification. */
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


/*
 * Arguments:
 * ethereum address, keccak256 hash of pubkey last 20 bytes, used to
 * shield the real pubkey.
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership.
 */
int verify_secp256k1_keccak_tron_sighash_all(unsigned char* message, unsigned char* eth_address, unsigned char* lock_bytes) {

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
//   /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
//   unsigned char eth_prefix[28]= {
// 0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69 ,0x67, 0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32
//   };
  /* personal hash, ethereum prefix  \x19TRON Signed Message:\n32  */
  unsigned char tron_prefix[24]= {
0x19, 
// 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 
0x54, 0x52, 0x4f, 0x4e,
0x20, 0x53, 0x69 ,0x67, 0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32
  };
  keccak_update(&sha3_ctx, tron_prefix, 24);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  /* verify signature with peronsal hash */
  return verify_signature(message, lock_bytes, eth_address);

}
