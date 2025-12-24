#include "mbedtls/ctr_drbg.h"

// if this is slow just static the entropy and ctr_drbg
void ED25519_FN(ed25519_randombytes_unsafe)(void *p, size_t len) {

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

  mbedtls_ctr_drbg_random(&ctr_drbg, p, len);

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}
