/* The file perform webauthn signature verification.
 *
 * https://webauthn.guide/#authentication For simplify we call a cell with this
 * lock a r1-lock cell.
 *
 * The signature build process is as follow:
 * 1. build a ckb transaction with r1-lock cell as input cells.
 * 2. calculate the tx message digest for the transaction as ckb system script
 * hash way, only except replace the blake2b hash algorithm with sha256.
 * 3. make a webauthn publicKeyCredentialRequestOptions for webauthn, take the
 * message digest of step2 as the challenge of client data.
 * 4. make a authentication request for user to get the assertion by calling
 * navigator.credentials.get()
 * 5. extract signature from the assertion, then build CKB tx witnesses based on
 * the signature and related info.
 *
 * lock bytes structures:
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

#include "common.h"
#include "protocol.h"
#include "pw_r1_helper.h"

#define R1_WITNESS_LOCK_SIZE 564
#define R1_SIGNATURE_SIZE 64
#define AUTHR_DATA_SIZE 37

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
  unsigned char prefix[13] = "\"challenge\":\"";
  int prefix_len = 13;

  /* ASCII code for \" */
  unsigned char suffix[1] = "\"";
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
 * @param message: transaction message digest, size is 32 bytes
 * @param lock_args: last 20 bytes sha256 hash of pubkey, used to shield
 * the real pubkey. size is 20 bytes
 * @param lock_bytes: transaction signature in witness.lock, size is 500 bytes
 *
 */
int validate_webauthn(unsigned char* message, unsigned char* lock_args,
                      unsigned char* lock_bytes, uint64_t lock_bytes_size) {
  if (lock_bytes_size != R1_WITNESS_LOCK_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  unsigned char pub_key[R1_PUBKEY_SIZE];

  /* check pubkey's hash equal to lock script args */
  unsigned char pub_key_hash[HASH_SIZE];
  memcpy(pub_key, lock_bytes, R1_PUBKEY_SIZE);
  sha256(pub_key, R1_PUBKEY_SIZE, pub_key_hash);

  if (memcmp(lock_args, pub_key_hash, LOCK_ARGS_SIZE) != 0) {
    return ERROR_WRONG_SIGNATURE;
  }

  int i = 0;
  for (i = R1_WITNESS_LOCK_SIZE - 1; i >= 0; i--) {
    if (lock_bytes[i] != 0) {
      break;
    }
  }
  int client_data_size =
      i - R1_PUBKEY_SIZE - R1_SIGNATURE_SIZE - AUTHR_DATA_SIZE + 1;

  /* verify challenge in client_data */
  int ret = verify_challenge_in_client_data(
      message,
      lock_bytes + R1_PUBKEY_SIZE + R1_SIGNATURE_SIZE + AUTHR_DATA_SIZE,
      client_data_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* build message_to_sign */
  u8 client_data_hash[HASH_SIZE];
  u8 message_to_sign[AUTHR_DATA_SIZE + HASH_SIZE];
  sha256(lock_bytes + R1_PUBKEY_SIZE + R1_SIGNATURE_SIZE + AUTHR_DATA_SIZE,
         client_data_size, client_data_hash);

  memcpy(message_to_sign, lock_bytes + R1_PUBKEY_SIZE + R1_SIGNATURE_SIZE,
         AUTHR_DATA_SIZE);
  memcpy(message_to_sign + AUTHR_DATA_SIZE, client_data_hash, HASH_SIZE);

  return verify_secp256r1_signature(pub_key, (const u8*)message_to_sign,
                                    lock_bytes + R1_PUBKEY_SIZE);
}
