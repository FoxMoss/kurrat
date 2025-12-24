#include <mbedtls/sha512.h>

typedef mbedtls_sha512_context ed25519_hash_context;

static void ed25519_hash_init(ed25519_hash_context *ctx) {
  mbedtls_sha512_init(ctx);
  mbedtls_sha512_starts(ctx, 0); /* 0 = SHA-512, 1 = SHA-384 */
}

static void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in,
                                size_t inlen) {
  mbedtls_sha512_update(ctx, in, inlen);
}

static void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
  mbedtls_sha512_finish(ctx, hash);
  mbedtls_sha512_free(ctx);
}

static void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
  mbedtls_sha512(in, inlen, hash, 0); /* 0 = SHA-512 */
}
