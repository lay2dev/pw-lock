/* for testing purpose */

#include "libsig.h"
#include "common.h"
#include "protocol.h"
#include "b64.h"

#define SHA256_CTX sha256_context
#define HASH_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 64
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define LOCK_SIZE 300
#define SIGNATURE_SIZE 64
#define AUTHR_DATA_SIZE 37

#define MAX_OUTPUT_LENGTH 64

#define ERROR_TOO_MANY_OUTPUT_CELLS -18
#define ERROR_WRONG_CHALLENGE -19
#define ERROR_WRONG_SIGNATURE -31

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

int pub_key_import_from_aff_buf(ec_pub_key *pub_key,
                                const ec_params *params,
                                const u8 *pub_key_buf,
                                u8 pub_key_buf_len,
                                ec_sig_alg_type ec_key_alg)
{

  int ret;
  aff_pt aff_pt;

  MUST_HAVE((pub_key != NULL) && (params != NULL));

  /* Import the aff point */
  ret = aff_pt_import_from_buf(&aff_pt, pub_key_buf, pub_key_buf_len, (ec_shortw_crv_src_t) & (params->ec_curve));

  if (ret < 0)
  {
    return -1;
  }

  ec_shortw_aff_to_prj(&(pub_key)->y, &aff_pt);

  /* Set key type and pointer to EC params */
  pub_key->key_type = ec_key_alg;
  pub_key->params = (const ec_params *)params;
  pub_key->magic = PUB_KEY_MAGIC;

  return 0;
}


int verify_challenge_in_client_data(const u8 * challenge, const u8 *client_data, u8 client_data_len){

    u8 challenge_b64[44];
    u8 challenge_decode[33];
    size_t challenge_decode_len = 33;

    u8 prefix[] = {34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34};
    int prefix_len = 13;
    u8 suffix[] = {34};
    int suffix_len = 1;

    int challenge_b64_start = 0;
    int challenge_b64_len = 0;

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

    if(challenge_b64_len <= 0){
        return -1;
    }

    memcpy(challenge_b64, client_data + challenge_b64_start, challenge_b64_len);


    while(challenge_b64_len < 44){
        challenge_b64[challenge_b64_len] = '=';
        challenge_b64_len++;
    }

    urlsafe_b64_decode((const char *)challenge_b64, 44, challenge_decode, &challenge_decode_len);
    if (challenge_decode_len == 32 && memcmp(challenge_decode, challenge, 32) == 0)
    {
        return 0;
    }

    return ERROR_WRONG_CHALLENGE;

}

int verify_secp256r1_signature(const u8 *pub_key_buffer, const u8 *data, const u8 *sig)
{

  int ret;
  u8 pub_key_buffer_len = PUBKEY_SIZE;
  u8 data_len = AUTHR_DATA_SIZE + HASH_SIZE;

  u8 siglen = SIGNATURE_SIZE;

  ec_params params;
  ec_pub_key pub_key;
  char *ec_name = "SECP256R1";
  u8 curve_name_len = 10;

  const ec_str_params *curve_params =
      ec_get_curve_params_by_name((const u8 *)ec_name, curve_name_len);
  import_params(&params, curve_params);

  if (curve_params == NULL)
  {
    return 11;
  }

  // ec_structured_pub_key_import_from_buf(&pub_key, &params, pub_key_buffer, pub_key_buffer_len, 1);
  ret = pub_key_import_from_aff_buf(&pub_key, &params, pub_key_buffer, pub_key_buffer_len, 1);

  if (ret < 0)
  {
    return ret;
  }

  struct ec_verify_context ctx;
  ec_verify_init(&ctx, &pub_key, sig, siglen, 1, 2);
  ec_verify_update(&ctx, (const u8 *)data, data_len);

  ret = ec_verify_finalize(&ctx);
  if(ret == 0){
    return ret;
  }else{
    return ERROR_WRONG_SIGNATURE;
  }
}

int main()
{

  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[LOCK_SIZE];

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS)
  {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE)
  {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK)
  {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != PUBKEY_SIZE)
  {
    return ERROR_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS)
  {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE)
  {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0)
  {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != LOCK_SIZE)
  {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);


  /* Load tx hash */
  unsigned char tx_hash[HASH_SIZE];
  len = HASH_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS)
  {
    return ret;
  }
  if (len != HASH_SIZE)
  {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[HASH_SIZE];
  SHA256_CTX sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, tx_hash, HASH_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  sha256_update(&sha256_ctx, (unsigned char *)&witness_len, sizeof(uint64_t));
  sha256_update(&sha256_ctx, temp, witness_len);

  // /* Digest same group witnesses */
  size_t i = 1;
  while (1)
  {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
      break;
    }
    if (ret != CKB_SUCCESS)
    {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE)
    {
      return ERROR_WITNESS_SIZE;
    }
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);
    i += 1;
  }
  /* Digest witnesses that not covered by inputs */
  i = calculate_inputs_len();
  while (1)
  {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND)
    {
      break;
    }
    if (ret != CKB_SUCCESS)
    {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE)
    {
      return ERROR_WITNESS_SIZE;
    }
    sha256_update(&sha256_ctx, (unsigned char *)&len, sizeof(uint64_t));
    sha256_update(&sha256_ctx, temp, len);

    i += 1;
  }
  sha256_final(&sha256_ctx, message);

  for (i = LOCK_SIZE - 1; i >= 0; i--){
    if(lock_bytes[i] != 0){
      break;
    }
  }
  int client_data_size = i - SIGNATURE_SIZE - AUTHR_DATA_SIZE + 1;

  /* verify challenge in client_data */
  ret = verify_challenge_in_client_data(message, lock_bytes + SIGNATURE_SIZE + AUTHR_DATA_SIZE, client_data_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* build message_to_sign */
  u8 client_data_hash[HASH_SIZE];
  u8 message_to_sign[AUTHR_DATA_SIZE + HASH_SIZE];
  sha256(lock_bytes + SIGNATURE_SIZE + AUTHR_DATA_SIZE, client_data_size, client_data_hash);

  memcpy(message_to_sign, lock_bytes + SIGNATURE_SIZE, AUTHR_DATA_SIZE);
  memcpy(message_to_sign + AUTHR_DATA_SIZE, client_data_hash, HASH_SIZE);

  return verify_secp256r1_signature(args_bytes_seg.ptr, (const u8 *)message_to_sign, lock_bytes);
}