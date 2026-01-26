#include "mbedtls/rsa.h"
#include <filesystem>
#include <format>
#include <thread>
extern "C" {
#include "donna/ed25519_donna_tor.h"
}
#include "keys.hpp"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "tor.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <tl/expected.hpp>
#include <unistd.h>
#include <vector>

#define ASSERT_ZERO(val, err)                                                  \
  {                                                                            \
    int ret = val;                                                             \
    if (ret != 0)                                                              \
      return tl::unexpected(err + std::string("(error code ") +                \
                            std::to_string(ret) + std::string(")"));           \
  }

#define ASSERT(val, eql, err)                                                  \
  if (val != eql) {                                                            \
    return tl::unexpected(err);                                                \
  }

#define ASSERT_NOT(val, eql, err)                                              \
  if (val == eql) {                                                            \
    return tl::unexpected(err);                                                \
  }

#define ASSERT_NON_NULL(val, err)                                              \
  if (val == NULL) {                                                           \
    return tl::unexpected(err);                                                \
  }

tl::expected<mbedtls_pk_context, std::string>
read_rsa_secret_key(const char *file, void *ctr_drbg) {
  mbedtls_pk_context id_pk;
  mbedtls_pk_init(&id_pk);
  ASSERT_ZERO(mbedtls_pk_parse_keyfile(&id_pk, file, "",
                                       mbedtls_ctr_drbg_random, ctr_drbg),
              "failed to parse rsa id key")
  return id_pk;
}

// "../keys/ed25519_master_id_secret_key"
tl::expected<std::vector<uint8_t>, std::string>
read_ed25519_secret_key(char *ed25519_master_id_secret_key_path) {
  FILE *master_id_secret_key = fopen(ed25519_master_id_secret_key_path, "rb");

  ASSERT_NON_NULL(master_id_secret_key, "faild to read ed25519 id key")

  ASSERT_ZERO(fseek(master_id_secret_key, 0x20, SEEK_SET),
              "failed to seek id secret key");

  std::vector<uint8_t> master_id_secret_key_raw;
  master_id_secret_key_raw.insert(master_id_secret_key_raw.end(), 64, 0);
  ASSERT(fread(master_id_secret_key_raw.data(), 1, 64, master_id_secret_key),
         64, "failed to read id secret key");
  fclose(master_id_secret_key);

  return master_id_secret_key_raw;
}

tl::expected<std::vector<uint8_t>, std::string>
create_cross_cert(std::vector<uint8_t> master_id_secret_key_raw,
                  mbedtls_pk_context id_pk, void *ctr_drbg) {
  std::vector<uint8_t> id_public_key;
  id_public_key.insert(id_public_key.end(), 32, 0);

  ASSERT_ZERO(ed25519_donna_pubkey(id_public_key.data(),
                                   master_id_secret_key_raw.data()),
              "failed to generate public key");

  std::vector<uint8_t> cert;
  cert.insert(cert.end(), id_public_key.begin(), id_public_key.end());

  uint32_t expiration = (time(NULL) + 86400) / (3600);
  expiration = htonl(expiration);
  cert.insert(cert.end(), (uint8_t *)&expiration,
              (uint8_t *)&expiration + sizeof(uint32_t));

  std::string prefix = "Tor TLS RSA/Ed25519 cross-certificate";
  std::vector<uint8_t> signing_object;
  signing_object.insert(signing_object.end(), prefix.begin(), prefix.end());
  signing_object.insert(signing_object.end(), cert.begin(), cert.end());

  unsigned char hash[32];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);
  ASSERT_ZERO(mbedtls_md_setup(&md_ctx,
                               mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0),
              "failed to setup signing hash");
  ASSERT_ZERO(mbedtls_md_starts(&md_ctx), "failed to start signing hash");
  ASSERT_ZERO(
      mbedtls_md_update(&md_ctx, signing_object.data(), signing_object.size()),
      "failed to update signing hash");
  ASSERT_ZERO(mbedtls_md_finish(&md_ctx, hash), "failed to finish hash");
  mbedtls_md_free(&md_ctx);

  uint8_t signature_raw[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(id_pk);
  ASSERT_NON_NULL(rsa, "failed to make id rsa context")

  ASSERT_ZERO(
      mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE),
      "failed to set rsa padding");

  ASSERT_ZERO(mbedtls_rsa_pkcs1_sign(rsa, mbedtls_ctr_drbg_random, ctr_drbg,
                                     MBEDTLS_MD_NONE, 32, hash, signature_raw),
              "failed to sign hash");

  size_t signature_raw_len = mbedtls_pk_get_len(&id_pk);
  ASSERT_NOT(signature_raw_len, 0, "failed to sign hash and get length")

  std::vector<uint8_t> signature;
  signature.insert(signature.end(), signature_raw,
                   signature_raw + signature_raw_len);

  cert.push_back((uint8_t)signature_raw_len);
  cert.insert(cert.end(), signature.begin(), signature.end());

  return cert;
}

tl::expected<std::vector<uint8_t>, std::string>
create_rsa_id_cert(mbedtls_pk_context id_pk, void *ctr_drbg) {
  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_x509write_crt_set_subject_key(&cert, &id_pk);
  mbedtls_x509write_crt_set_issuer_key(&cert, &id_pk);

  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_mpi serial;
  mbedtls_mpi_init(&serial);

  // 2000 is just some number, set_serial is deprecated so we should switch this
  // out if we want the code to be pretty
  ASSERT_ZERO(mbedtls_mpi_lset(&serial, 2000), "failed to create serial")
  ASSERT_ZERO(mbedtls_x509write_crt_set_serial(&cert, &serial),
              "failed to set x509 serial");
  mbedtls_mpi_free(&serial);

  // jank bad utc time calculator because not debugging validity timestamps
  auto now = std::chrono::utc_clock::now();
  auto expires = now + std::chrono::utc_seconds::duration(60 * 60 * 24 * 365);
  auto before = now - std::chrono::utc_seconds::duration(60 * 60 * 24 * 365);
  std::string expires_str = std::format("{:%Y}1231235959", expires);
  std::string before_str = std::format("{:%Y}1231235959", before);

  ASSERT_ZERO(mbedtls_x509write_crt_set_validity(&cert, before_str.c_str(),
                                                 expires_str.c_str()),
              "failed to set x509 validity")

  mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
  ASSERT_ZERO(
      mbedtls_x509write_crt_set_issuer_name(&cert, "C=US,O=FOX,CN=FoxMoss"),
      "failed to set x509 issuer name")
  ASSERT_ZERO(
      mbedtls_x509write_crt_set_subject_name(&cert, "C=US,O=FOX,CN=FoxMoss"),
      "failed to set x509 subject name")

  uint8_t der_buf[4096];
  int der_len = mbedtls_x509write_crt_der(&cert, der_buf, 4096,
                                          mbedtls_ctr_drbg_random, ctr_drbg);

  std::vector<uint8_t> der;
  der.insert(der.end(), (uint8_t *)der_buf + (4096 - der_len),
             (uint8_t *)der_buf + 4096);

  mbedtls_x509write_crt_free(&cert);

  return der;
}

tl::expected<std::vector<uint8_t>, std::string>
create_id_cert(std::vector<uint8_t> master_id_secret_key_raw,
               std::vector<uint8_t> signing_secret_key) {
  // signing key
  std::vector<uint8_t> signing_public_key;
  signing_public_key.insert(signing_public_key.end(), 32, 0);
  ed25519_donna_pubkey(signing_public_key.data(), signing_secret_key.data());

  std::vector<uint8_t> id_public_key;
  id_public_key.insert(id_public_key.end(), 32, 0);

  ed25519_donna_pubkey(id_public_key.data(), master_id_secret_key_raw.data());

  // gen that cert

  std::vector<uint8_t> cert;
  cert.push_back(1);    // version
  cert.push_back(0x04); // IDENTITY_V_SIGNING

  uint32_t expiration = (time(NULL) + 86400) / (3600);
  expiration = htonl(expiration);
  cert.insert(cert.end(), (uint8_t *)&expiration,
              (uint8_t *)&expiration + sizeof(uint32_t));

  cert.push_back(0x01); // certified ed25519

  cert.insert(cert.end(), signing_public_key.begin(), signing_public_key.end());

  cert.push_back(0x01); // 1 ext

  uint16_t ext_len = htons(32);
  cert.insert(cert.end(), (uint8_t *)&ext_len,
              (uint8_t *)&ext_len + sizeof(uint16_t));

  cert.push_back(0x04); // Signed-with-ed25519-key extension
  cert.push_back(0x01); // yes effects validation

  cert.insert(cert.end(), id_public_key.begin(), id_public_key.end());

  unsigned char signature[64];
  ASSERT_ZERO(ed25519_donna_sign(signature, cert.data(), cert.size(),
                                 master_id_secret_key_raw.data(),
                                 id_public_key.data()),
              "failed to sign ed25519 cert");

  cert.insert(cert.end(), signature, signature + 64);

  return cert;
}

tl::expected<std::vector<uint8_t>, std::string>
create_tls_cert(std::vector<uint8_t> signing_secret_key,
                std::vector<uint8_t> subject) {

  std::vector<uint8_t> signing_public_key;
  signing_public_key.insert(signing_public_key.end(), 32, 0);

  ed25519_donna_pubkey(signing_public_key.data(), signing_secret_key.data());

  std::vector<uint8_t> cert;
  cert.push_back(1);    // version
  cert.push_back(0x05); // A TLS certificate signed with ed25519 signing key

  uint32_t expiration = (time(NULL) + 86400) / (3600);
  expiration = htonl(expiration);
  cert.insert(cert.end(), (uint8_t *)&expiration,
              (uint8_t *)&expiration + sizeof(uint32_t));

  cert.push_back(0x03); // SHA256 hash of an X.509 certificate

  cert.insert(cert.end(), subject.begin(), subject.end());

  unsigned char signature[64];
  ASSERT_ZERO(ed25519_donna_sign(signature, cert.data(), cert.size(),
                                 signing_secret_key.data(),
                                 signing_public_key.data()),
              "failed to sign tls cert");

  cert.insert(cert.end(), signature, signature + 64);

  return cert;
}

// "../keys/ed25519_signing_secret_key"
tl::expected<std::vector<uint8_t>, std::string>
read_ed25519_signing_key(const char *ed25519_signing_secret_key) {
  FILE *signing_secret_key = fopen(ed25519_signing_secret_key, "rb");

  ASSERT_ZERO(fseek(signing_secret_key, 0x20, SEEK_SET),
              "failed to seek ed25519 signing key")

  std::vector<uint8_t> signing_secret_key_vec;
  signing_secret_key_vec.insert(signing_secret_key_vec.end(), 64, 0);

  ASSERT(fread(signing_secret_key_vec.data(), 1, 64, signing_secret_key), 64,
         "failed to read ed25519 signing key")
  fclose(signing_secret_key);

  return signing_secret_key_vec;
}

tl::expected<LinkKeys, std::string>
create_link_cert(const std::vector<uint8_t> &signing_secret_key) {
  uint8_t link_public_key[32];
  uint8_t link_secret_key[64];

  ed25519_donna_keygen(link_public_key, link_secret_key);

  std::vector<uint8_t> signing_public_key;
  signing_public_key.insert(signing_public_key.end(), 32, 0);

  ed25519_donna_pubkey(signing_public_key.data(), signing_secret_key.data());

  std::vector<uint8_t> cert;
  cert.push_back(1); // version
  cert.push_back(
      0x06); // Ed25519 authentication key signed with ed25519 signing key

  uint32_t expiration = (time(NULL) + 86400) / (3600);
  expiration = htonl(expiration);
  cert.insert(cert.end(), (uint8_t *)&expiration,
              (uint8_t *)&expiration + sizeof(uint32_t));

  cert.push_back(0x01); // certified ed25519
  cert.insert(cert.end(), link_public_key, link_public_key + 32);

  cert.push_back(0x00); // no extensions

  unsigned char signature[64];
  ASSERT_ZERO(ed25519_donna_sign(signature, cert.data(), cert.size(),
                                 signing_secret_key.data(),
                                 signing_public_key.data()),
              "failed to sign cert")

  cert.insert(cert.end(), signature, signature + 64);

  std::vector<uint8_t> link_public_key_v, link_secret_key_v;
  link_public_key_v.insert(link_public_key_v.end(), link_public_key,
                           link_public_key + 32);
  link_secret_key_v.insert(link_secret_key_v.end(), link_secret_key,
                           link_secret_key + 64);

  LinkKeys keys{.link_public_key = link_public_key_v,
                .link_secret_key = link_secret_key_v,
                .cert = cert};
  return keys;
}

tl::expected<KeysParsed, std::string>
parse_keys_from_folder(std::filesystem::path folder_path, void *ctr_drbg) {
  try {

    KeysParsed parsed;

    if (!std::filesystem::exists(folder_path))
      return tl::unexpected("failed to find key folder");

    auto secret_id_key_path = folder_path / "secret_id_key";

    if (!std::filesystem::exists(secret_id_key_path))
      return tl::unexpected("failed to find secret_id_key");

    auto secret_id_key_parsed =
        read_rsa_secret_key(secret_id_key_path.c_str(), ctr_drbg);
    UNWRAP(secret_id_key_parsed)
    parsed.secret_id_key = secret_id_key_parsed.value();

    auto master_id_secret_key_raw_path =
        folder_path / "ed25519_master_id_secret_key";

    if (!std::filesystem::exists(master_id_secret_key_raw_path))
      return tl::unexpected("failed to find ed25519_master_id_secret_key");

    auto master_id_secret_key_raw_parsed =
        read_ed25519_signing_key(master_id_secret_key_raw_path.c_str());
    UNWRAP(master_id_secret_key_raw_parsed)

    parsed.master_id_secret_key_raw = master_id_secret_key_raw_parsed.value();

    auto signing_secret_key_path = folder_path / "ed25519_signing_secret_key";

    if (!std::filesystem::exists(signing_secret_key_path))
      return tl::unexpected("failed to find ed25519_signing_secret_key");

    auto signing_secret_key_parsed =
        read_ed25519_signing_key(signing_secret_key_path.c_str());
    UNWRAP(signing_secret_key_parsed)

    parsed.signing_secret_key = signing_secret_key_parsed.value();

    auto ntor_key_path = folder_path / "secret_onion_key_ntor";

    if (!std::filesystem::exists(ntor_key_path))
      return tl::unexpected("failed to find secret_onion_key_ntor");

    auto ntor_key_parsed = read_ed25519_signing_key(ntor_key_path.c_str());
    UNWRAP(ntor_key_parsed)

    parsed.ntor_key = ntor_key_parsed.value();

    return parsed;
  } catch (std::exception &e) {
    return tl::unexpected(e.what());
  }
  return tl::unexpected("failed to try catch or return error value");
}
