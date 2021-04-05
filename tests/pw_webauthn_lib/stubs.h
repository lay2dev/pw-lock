#ifndef PW_LOCK_TESTS_SECP256R1_SHA256_SIGHASH_STUBS_H_
#define PW_LOCK_TESTS_SECP256R1_SHA256_SIGHASH_STUBS_H_

int aff_pt_import_from_buf(aff_pt_t pt,
                           const u8 *pt_buf,
                           u16 pt_buf_len, ec_shortw_crv_src_t crv) {
  return 0;
}


const ec_str_params *ec_get_curve_params_by_name(const u8 *ec_name,
                                                 u8 ec_name_len) {
  return NULL;
}

void ec_shortw_aff_to_prj(prj_pt_t out, aff_pt_src_t in) {

}

int ec_verify_finalize(struct ec_verify_context *ctx) {
  return 0;
}

int ec_verify_init(struct ec_verify_context *ctx, const ec_pub_key *pub_key,
                   const u8 *sig, u8 siglen,
                   ec_sig_alg_type sig_type, hash_alg_type hash_type)
{
  return 0;
}
int ec_verify_update(struct ec_verify_context *ctx,
                     const u8 *chunk, u32 chunklen)
{
  return 0;

}

void import_params(ec_params *out_params, const ec_str_params *in_str_params)
{

}

void sha256(const u8 *input, u32 ilen, u8 output[SHA256_DIGEST_SIZE]) {
}
void sha256_final(sha256_context *ctx, u8 output[SHA256_DIGEST_SIZE]) {
}
void sha256_init(sha256_context *ctx)
{

}

void sha256_update(sha256_context *ctx, const u8 *input, u32 ilen)
{

}
#endif //PW_LOCK_TESTS_SECP256R1_SHA256_SIGHASH_STUBS_H_
