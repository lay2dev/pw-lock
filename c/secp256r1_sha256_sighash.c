/* ES256 signature verification script for Webauthn scenario
 *
 * This script can only verify the signature from webauthn api.
 *https://webauthn.guide/#authentication For simplify we call a cell with this
 *lock a r1-lock cell.
 *
 * The signature build process is as follow:
 * 1. build a ckb transaction with r1-lock cell as input cells.
 * 2. calculate the tx message digest for the transaction as ckb system script
 *hash way, only except replace the blake2b hash algorithm with sha256.
 * 3. make a webauthn publicKeyCredentialRequestOptions for webauthn, take the
 *message digest of step2 as the challenge of client data.
 * 4. make a authentication request for user to get the assertion by calling
 *navigator.credentials.get()
 * 5. extract signature from the assertion, then build CKB tx witnesses based on
 *the signature and related info.
 *
 * witness structures:
 *|-----------|-----------|-----------|------------|-------------|-------------|
 *|---0-31----|---32-63 --|---64-95---|---96-127---|---128-164---|---165-563---|
 *|  pubkey.x |  pubkey.y |  sig.r    |  sig.s     |    authr    | client_data |
 *|-----------|-----------|-----------|------------|-------------|-------------|
 *|-----------|-----------|-----------|------------|-------------|-------------|
 *
 * client_data example:
 *{
 *  "type": "webauthn.get",
 *  "challenge": "S1TsVwxDkO4ZbNa2EJvywNWS9prOay0x_uCTIv4cHs4",
 *  "origin": "https://r1-demo.ckb.pw",
 *  "crossOrigin": false
 *}
 * we need to set challenge of client data json with CKB tx message digest
 *
 */

#include "blake2b.h"
#include "common.h"
#include "protocol.h"
#include "pw_r1_helper.h"

#define SHA256_CTX sha256_context
#define HASH_SIZE 32
#define LOCK_ARGS_SIZE 20
#define R1_PUBKEY_SIZE 64  // UNCOMPRESSED PUB KEY (x, y)
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define WITNESS_LOCK_SIZE 564
#define SIGNATURE_SIZE 64
#define AUTHR_DATA_SIZE 37

#define MAX_OUTPUT_LENGTH 64

#define ERROR_TOO_MANY_OUTPUT_CELLS -18
#define ERROR_WRONG_CHALLENGE -19
#define ERROR_WRONG_SIGNATURE -31

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

/**
 * check the challenge of client data json is equal to tx message digest
 * @param digest_message transation digest message
 * @param client_data the client data represents the contextual bindings of both
 * the WebAuthn Relying Party and the client
 * @param client_data_len the length of client data
 *
 */
int verify_challenge_in_client_data(const u8* digest_message,
                                    const u8* client_data, u8 client_data_len) {
  u8 challenge_b64[44];
  u8 challenge_decode[33];
  size_t challenge_decode_len = 33;

  /*  ASCII code for string \"challenge\":\"  */
  u8 prefix[] = {34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34};
  int prefix_len = 13;

  /* ASCII code for \" */
  u8 suffix[] = {34};
  int suffix_len = 1;

  int challenge_b64_start = 0;
  int challenge_b64_len = 0;

  /* extract challenge value from client data*/
  int i = 0;
  while (i < client_data_len - prefix_len) {
    if (memcmp(client_data + i, prefix, prefix_len) == 0) {
      int j = i + prefix_len;

      while (j < client_data_len) {
        if (memcmp(client_data + j, suffix, suffix_len) == 0) {
          challenge_b64_len = j - i - prefix_len;
          break;
        }
        j++;
      }

      challenge_b64_start = i + prefix_len;
      if (challenge_b64_len > 0) {
        break;
      }
    }
    i++;
  }

  if (challenge_b64_len <= 0) {
    return -1;
  }

  memcpy(challenge_b64, client_data + challenge_b64_start, challenge_b64_len);

  while (challenge_b64_len < 44) {
    challenge_b64[challenge_b64_len] = '=';
    challenge_b64_len++;
  }

  urlsafe_b64_decode((const char*)challenge_b64, 44, challenge_decode,
                     &challenge_decode_len);

  /* compare the challenge of client data with the tx message digest */
  if (challenge_decode_len == 32 &&
      memcmp(challenge_decode, digest_message, 32) == 0) {
    return 0;
  }

  return ERROR_WRONG_CHALLENGE;
}

/**
 * The script args part should contain first 20 bytes of sha256 hash of public
 * key. This is usded to shield the real public key.
 *
 * The first witness, or the first witness of the same index as the first input
 * cell using current lock script, should be a
 * [WitnessArgs](https://github.com/nervosnetwork/ckb/blob/1df5f2c1cbf07e04622fb8faa5b152c1af7ae341/util/types/schemas/blockchain.mol#L106)
 * object in molecule serialization format.
 *
 * The lock filed of said WitnessArgs should contain 564-byte info for signature
 * verification, including public key, signature, authr data and client data
 * json from webauth assertion.
 *
 */
int main() {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[WITNESS_LOCK_SIZE];
  unsigned char pub_key[R1_PUBKEY_SIZE];

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t*)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != LOCK_ARGS_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != WITNESS_LOCK_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  /* check pubkey's hash equal to lock script args */
  unsigned char pub_key_hash[HASH_SIZE];
  for (int j = 0; j < HASH_SIZE; j++) pub_key_hash[j] = 0;
  memcpy(pub_key, lock_bytes_seg.ptr, R1_PUBKEY_SIZE);
  sha256(pub_key, R1_PUBKEY_SIZE, pub_key_hash);
  if (memcmp(args_bytes_seg.ptr, pub_key_hash, LOCK_ARGS_SIZE) != 0) {
    return ERROR_WRONG_SIGNATURE;
  }

  /* Load tx hash */
  unsigned char tx_hash[HASH_SIZE];
  len = HASH_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[HASH_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, HASH_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, HASH_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void*)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (unsigned char*)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (unsigned char*)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  /* Digest witnesses that not covered by inputs */
  i = calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    blake2b_update(&blake2b_ctx, (unsigned char*)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);

    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, HASH_SIZE);

  for (i = WITNESS_LOCK_SIZE - 1; i >= 0; i--) {
    if (lock_bytes[i] != 0) {
      break;
    }
  }
  int client_data_size =
      i - R1_PUBKEY_SIZE - SIGNATURE_SIZE - AUTHR_DATA_SIZE + 1;

  /* verify challenge in client_data */
  ret = verify_challenge_in_client_data(
      message, lock_bytes + R1_PUBKEY_SIZE + SIGNATURE_SIZE + AUTHR_DATA_SIZE,
      client_data_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* build message_to_sign */
  u8 client_data_hash[HASH_SIZE];
  u8 message_to_sign[AUTHR_DATA_SIZE + HASH_SIZE];
  sha256(lock_bytes + R1_PUBKEY_SIZE + SIGNATURE_SIZE + AUTHR_DATA_SIZE,
         client_data_size, client_data_hash);

  memcpy(message_to_sign, lock_bytes + R1_PUBKEY_SIZE + SIGNATURE_SIZE,
         AUTHR_DATA_SIZE);
  memcpy(message_to_sign + AUTHR_DATA_SIZE, client_data_hash, HASH_SIZE);

  return verify_secp256r1_signature(pub_key, (const u8*)message_to_sign,
                                    lock_bytes + R1_PUBKEY_SIZE);
}