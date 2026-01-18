#include <filesystem>
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
#include <linux/tls.h>
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

void add_padding_b64(std::string &b64) {
  while (b64.size() % 4 != 0) {
    b64.push_back('=');
  }
}

tl::expected<TorConnection, std::string>
make_tor_connection(mbedtls_pk_context secret_id_key,
                    std::vector<uint8_t> master_id_secret_key_raw,
                    std::vector<uint8_t> signing_secret_key,
                    std::vector<uint8_t> ntor_key, void *ctr_drbg,
                    std::string remote_ntor_b64,
                    std::string remote_identity_b64, uint32_t other_addr_raw,
                    mbedtls_ssl_context ssl_context) {
  uint8_t der_buf[4096];
  uint8_t *der_buf_cursor = der_buf + 4096;
  int der_len =
      mbedtls_pk_write_pubkey(&der_buf_cursor, der_buf, &secret_id_key);

  std::vector<uint8_t> local_KP_relayid_rsa;
  local_KP_relayid_rsa.insert(local_KP_relayid_rsa.end(),
                              (uint8_t *)der_buf + (4096 - der_len),
                              der_buf + 4096);

  uint8_t local_hash_rsa[32];
  mbedtls_sha256(local_KP_relayid_rsa.data(), local_KP_relayid_rsa.size(),
                 local_hash_rsa, false);

  std::vector<uint8_t> id_public_key;
  id_public_key.insert(id_public_key.end(), 32, 0);

  ed25519_donna_pubkey(id_public_key.data(), master_id_secret_key_raw.data());

  // get responder x509
  const mbedtls_x509_crt *responder_cert =
      mbedtls_ssl_get_peer_cert(&ssl_context);
  std::vector<uint8_t> responder_data;
  responder_data.insert(responder_data.end(), responder_cert->raw.p,
                        responder_cert->raw.p + responder_cert->raw.len);

  std::vector<uint8_t> responder_cert_hash;
  responder_cert_hash.insert(responder_cert_hash.end(), 32, 0);
  mbedtls_sha256(responder_data.data(), responder_data.size(),
                 responder_cert_hash.data(), 0);

  // keying_material
  std::vector<uint8_t> keying_material;
  keying_material.insert(keying_material.end(), 32, 0);
  std::string label = "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003";
  mbedtls_ssl_export_keying_material(&ssl_context, keying_material.data(), 32,
                                     label.c_str(), label.size(),
                                     local_hash_rsa, 32, true);
  // IDENTITY_V_SIGNING
  auto id_cert = create_id_cert(master_id_secret_key_raw, signing_secret_key);
  UNWRAP(id_cert)

  // SIGNING_V_TLS_CERT
  auto tls_cert = create_tls_cert(signing_secret_key, responder_cert_hash);
  UNWRAP(tls_cert)

  // SIGNING_V_LINK_AUTH
  auto link_cert = create_link_cert(signing_secret_key);
  UNWRAP(link_cert)

  // RSA_ID_X509
  auto rsa_id_cert = create_rsa_id_cert(secret_id_key, ctr_drbg);
  UNWRAP(rsa_id_cert)

  // RSA_ID_V_IDENTITY
  auto cross_cert =
      create_cross_cert(master_id_secret_key_raw, secret_id_key, ctr_drbg);
  UNWRAP(cross_cert)

  // things we get from the consesus
  std::vector<uint8_t> remote_identity_digest;
  remote_identity_digest.insert(remote_identity_digest.end(), 20, 0);

  add_padding_b64(remote_identity_b64);
  size_t remote_identity_len;
  mbedtls_base64_decode((unsigned char *)remote_identity_digest.data(), 20,
                        &remote_identity_len,
                        (const unsigned char *)remote_identity_b64.c_str(),
                        remote_identity_b64.size());

  std::vector<uint8_t> remote_ntor_pub_key;
  remote_ntor_pub_key.insert(remote_ntor_pub_key.end(), 32, 0);
  add_padding_b64(remote_ntor_b64);
  size_t remote_ntor_len;
  mbedtls_base64_decode(
      (unsigned char *)remote_ntor_pub_key.data(), 32, &remote_ntor_len,
      (const unsigned char *)remote_ntor_b64.c_str(), remote_ntor_b64.size());

  std::string my_addr_str = "127.0.0.1";

  struct in_addr my_addr;
  inet_pton(AF_INET, my_addr_str.c_str(), &my_addr);
  uint32_t my_addr_raw = my_addr.s_addr;

  // start the tor connection

  TorConnection connection = TorConnection(
      {{0x04, id_cert.value()},
       {0x06, link_cert->cert},
       /*{0x05, tls_cert},*/
       {0x02, rsa_id_cert.value()},
       {0x07, cross_cert.value()}},
      id_public_key, link_cert->link_secret_key, link_cert->link_public_key,
      my_addr_raw, other_addr_raw, &secret_id_key, responder_data,
      keying_material, ntor_key, remote_identity_digest, remote_ntor_pub_key);

  return connection;
}
