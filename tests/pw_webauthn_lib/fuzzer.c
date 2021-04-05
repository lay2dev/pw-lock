#include "ckb_syscalls.h"
#include "webauthn/pw_webauthn_lib.c"
#include "stubs.h"


/**
 * @param message: transaction message digest, size is 32 bytes
 * @param lock_args: last 20 bytes sha256 hash of pubkey, used to shield
 * the real pubkey. size is 20 bytes
 * @param lock_bytes: transaction signature in witness.lock, size is 500 bytes
 *
 */
int validate_webauthn(unsigned char* message, unsigned char* lock_args,
                      unsigned char* lock_bytes, uint64_t lock_bytes_size);


int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  if (size < (564+20+32)) {
    return 0;
  }
  validate_webauthn(data, data+32, data+32+20, 564);
  return 0;
}
