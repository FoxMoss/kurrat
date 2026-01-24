// this is a quick and dirty program to generate the consesus docs from a
// /var/lib/tor/keys directory for use in create2 cell testing

#include "mbedtls/base64.h"
#include "mbedtls/pk.h"

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/sha1.h>
#include <mbedtls/ssl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sodium.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

int main() {
  FILE *signing_ntor_key = fopen("secret_onion_key_ntor", "rb");

  fseek(signing_ntor_key, 0x20, SEEK_SET);

  std::vector<uint8_t> ntor_key;
  ntor_key.insert(ntor_key.end(), 64, 0);
  fread(ntor_key.data(), 1, 64, signing_ntor_key);
  fclose(signing_ntor_key);

  std::vector<uint8_t> ntor_public_key;

  ntor_public_key.insert(ntor_public_key.end(), crypto_scalarmult_SCALARBYTES,
                         0);
  crypto_scalarmult_curve25519_base(ntor_public_key.data(), ntor_key.data());

  uint8_t ntor_pub_key_cstr[1024];
  size_t ntor_pub_key_cstr_len;
  mbedtls_base64_encode(ntor_pub_key_cstr, 1024, &ntor_pub_key_cstr_len,
                        ntor_public_key.data(), ntor_public_key.size());

  std::string ntor_pub_b64;
  ntor_pub_b64.insert(ntor_pub_b64.end(), ntor_pub_key_cstr,
                      ntor_pub_key_cstr + ntor_pub_key_cstr_len);

  printf("ntor-onion-key \t\t\t\t %s\n", ntor_pub_b64.c_str());

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *)"client", 6);

  mbedtls_pk_context secret_id_pk;

  mbedtls_pk_init(&secret_id_pk);
  mbedtls_pk_parse_keyfile(&secret_id_pk, "secret_id_key", "",
                           mbedtls_ctr_drbg_random, &ctr_drbg);

  uint8_t id_pub_key_raw[4096];
  uint8_t *id_pub_key_raw_cursor = id_pub_key_raw + 4096;

  int id_pub_key_raw_len = mbedtls_pk_write_pubkey(
      &id_pub_key_raw_cursor, id_pub_key_raw, &secret_id_pk);

  mbedtls_sha1_context id_pub_key_hash;
  mbedtls_sha1_init(&id_pub_key_hash);
  mbedtls_sha1_starts(&id_pub_key_hash);
  mbedtls_sha1_update(&id_pub_key_hash,
                      id_pub_key_raw + 4096 - id_pub_key_raw_len,
                      id_pub_key_raw_len);

  uint8_t id_pub_key_hash_raw[20];
  mbedtls_sha1_finish(&id_pub_key_hash, id_pub_key_hash_raw);

  uint8_t id_pub_key_cstr[1024];
  size_t id_pub_key_cstr_len;
  mbedtls_base64_encode(id_pub_key_cstr, 1024, &id_pub_key_cstr_len,
                        id_pub_key_hash_raw, 20);

  std::string id_pub_b64;
  id_pub_b64.insert(id_pub_b64.end(), id_pub_key_cstr,
                    id_pub_key_cstr + id_pub_key_cstr_len);

  printf("identity SHA1(DER(KP_relayid_rsa)) \t %s\n", id_pub_b64.c_str());
}
