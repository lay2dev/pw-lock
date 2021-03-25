#include "b64.h"
#include "libsig.h"

#define HASH_SIZE 32
#define LOCK_ARGS_SIZE 20
#define R1_PUBKEY_SIZE 64  // UNCOMPRESSED PUB KEY (x, y)
#define TEMP_SIZE 32768
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define R1_WITNESS_LOCK_SIZE 564
#define R1_SIGNATURE_SIZE 64
#define AUTHR_DATA_SIZE 37
#define MIN_CLIENT_DATA_SIZE 64

enum ErrorCode {
  /* 0 is the only success code. We can use 0 directly. */

  ERROR_SIG_BUFFER_SIZE = 61,
  ERROR_MESSAGE_SIZE,
  ERROR_WRONG_CHALLENGE,
  ERROR_WRONG_PUBKEY,
  ERROR_WINTESS_LOCK_SIZE,
  ERROR_R1_SIGNATURE_VERFICATION,
  ERROR_CLIENT_DATA_SIZE,

};

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

int pub_key_import_from_aff_buf(ec_pub_key* pub_key, const ec_params* params,
                                const u8* pub_key_buf, u8 pub_key_buf_len,
                                ec_sig_alg_type ec_key_alg) {
  int ret;
  aff_pt aff_pt;

  MUST_HAVE((pub_key != NULL) && (params != NULL));

  /* Import the aff point */
  ret = aff_pt_import_from_buf(&aff_pt, pub_key_buf, pub_key_buf_len,
                               (ec_shortw_crv_src_t) & (params->ec_curve));

  if (ret < 0) {
    return ERROR_WRONG_PUBKEY;
  }

  ec_shortw_aff_to_prj(&(pub_key)->y, &aff_pt);

  /* Set key type and pointer to EC params */
  pub_key->key_type = ec_key_alg;
  pub_key->params = (const ec_params*)params;
  pub_key->magic = PUB_KEY_MAGIC;

  return CKB_SUCCESS;
}

/**
 * verify secp256 r1 signature with pubkey
 *
 * @param pub_key_buffer public key for signature verification
 * @param data
 * @param sig ES256 signature from web authn
 */
int verify_secp256r1_signature(const u8* pub_key_buffer, const u8* data,
                               const u8* sig) {
  int ret;
  u8 pub_key_buffer_len = R1_PUBKEY_SIZE;
  u8 data_len = AUTHR_DATA_SIZE + HASH_SIZE;

  u8 siglen = R1_SIGNATURE_SIZE;

  ec_params params;
  ec_pub_key pub_key;
  char* ec_name = "SECP256R1";
  u8 curve_name_len = 10;

  const ec_str_params* curve_params =
      ec_get_curve_params_by_name((const u8*)ec_name, curve_name_len);
  import_params(&params, curve_params);

  if (curve_params == NULL) {
    return 11;
  }

  ret = pub_key_import_from_aff_buf(&pub_key, &params, pub_key_buffer,
                                    pub_key_buffer_len, 1);

  if (ret != CKB_SUCCESS) {
    return ret;
  }

  struct ec_verify_context ctx;
  ec_verify_init(&ctx, &pub_key, sig, siglen, 1, 2);
  ec_verify_update(&ctx, (const u8*)data, data_len);

  ret = ec_verify_finalize(&ctx);
  if (ret == CKB_SUCCESS) {
    return ret;
  } else {
    return ERROR_R1_SIGNATURE_VERFICATION;
  }
}