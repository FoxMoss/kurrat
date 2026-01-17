#include <thread>
extern "C" {
#include "donna/ed25519_donna_tor.h"
}
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
#include <unistd.h>
#include <vector>

void tls_key_export_callback(void *p_expkey, mbedtls_ssl_key_export_type type,
                             const unsigned char *secret, size_t secret_len,
                             const unsigned char client_random[32],
                             const unsigned char server_random[32],
                             mbedtls_tls_prf_types tls_prf_type) {

  static FILE *keylog_file;
  if (keylog_file == nullptr) {
    keylog_file = fopen("sslkeylog.txt", "w");
  }

  fprintf(keylog_file, "CLIENT_RANDOM ");

  for (int i = 0; i < 32; i++) {
    fprintf(keylog_file, "%02x", client_random[i]);
  }

  fprintf(keylog_file, " ");

  for (int i = 0; i < secret_len; i++) {
    fprintf(keylog_file, "%02x", secret[i]);
  }

  fprintf(keylog_file, "\n");
  fflush(keylog_file);
}

struct LinkKeys {
  std::vector<uint8_t> link_public_key, link_secret_key, cert;
};

std::vector<uint8_t> create_cross_cert(void *ctr_drbg) {

  mbedtls_pk_context id_pk;
  mbedtls_pk_init(&id_pk);
  mbedtls_pk_parse_keyfile(&id_pk, "../keys/secret_id_key", "",
                           mbedtls_ctr_drbg_random, ctr_drbg);

  FILE *master_id_secret_key =
      fopen("../keys/ed25519_master_id_secret_key", "rb");

  fseek(master_id_secret_key, 0x20, SEEK_SET);

  std::vector<uint8_t> master_id_secret_key_raw;
  master_id_secret_key_raw.insert(master_id_secret_key_raw.end(), 64, 0);
  fread(master_id_secret_key_raw.data(), 1, 64, master_id_secret_key);
  fclose(master_id_secret_key);

  std::vector<uint8_t> id_public_key;
  id_public_key.insert(id_public_key.end(), 32, 0);

  ed25519_donna_pubkey(id_public_key.data(), master_id_secret_key_raw.data());

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
  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&md_ctx);
  mbedtls_md_update(&md_ctx, signing_object.data(), signing_object.size());
  mbedtls_md_finish(&md_ctx, hash);
  mbedtls_md_free(&md_ctx);

  FILE *signing_object_file = fopen("signing_object.log", "w");
  fwrite(hash, 32, 1, signing_object_file);
  fclose(signing_object_file);

  uint8_t signature_raw[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
  size_t signature_raw_len;
  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(id_pk);

  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

  mbedtls_rsa_pkcs1_sign(rsa, mbedtls_ctr_drbg_random, ctr_drbg,
                         MBEDTLS_MD_NONE, 32, hash, signature_raw);
  signature_raw_len = mbedtls_pk_get_len(&id_pk);

  std::vector<uint8_t> signature;
  signature.insert(signature.end(), signature_raw,
                   signature_raw + signature_raw_len);

  cert.push_back((uint8_t)signature_raw_len);
  cert.insert(cert.end(), signature.begin(), signature.end());

  return cert;
}

std::vector<uint8_t> create_rsa_id_cert(void *ctr_drbg) {
  mbedtls_pk_context id_pk;
  mbedtls_pk_init(&id_pk);
  mbedtls_pk_parse_keyfile(&id_pk, "../keys/secret_id_key", "",
                           mbedtls_ctr_drbg_random, ctr_drbg);

  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_x509write_crt_set_subject_key(&cert, &id_pk);
  mbedtls_x509write_crt_set_issuer_key(&cert, &id_pk);

  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);

  mbedtls_mpi serial;
  mbedtls_mpi_init(&serial);
  // 2000 is just some number, set_serial is deprecated so we should switch this
  // out if we want the code to be pretty
  mbedtls_mpi_lset(&serial, 2000);
  mbedtls_x509write_crt_set_serial(&cert, &serial);
  mbedtls_mpi_free(&serial);

  // jank bad utc time calculator because not debugging validity timestamps
  auto now = std::chrono::utc_clock::now();
  auto expires = now + std::chrono::utc_seconds::duration(60 * 60 * 24 * 365);
  auto before = now - std::chrono::utc_seconds::duration(60 * 60 * 24 * 365);
  std::string expires_str = std::format("{:%Y}1231235959", expires);
  std::string before_str = std::format("{:%Y}1231235959", before);

  mbedtls_x509write_crt_set_validity(&cert, before_str.c_str(),
                                     expires_str.c_str());

  mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
  mbedtls_x509write_crt_set_issuer_name(&cert, "C=US,O=FOX,CN=FoxMoss");
  mbedtls_x509write_crt_set_subject_name(&cert, "C=US,O=FOX,CN=FoxMoss");

  uint8_t der_buf[4096];
  int der_len = mbedtls_x509write_crt_der(&cert, der_buf, 4096,
                                          mbedtls_ctr_drbg_random, ctr_drbg);

  std::vector<uint8_t> der;
  der.insert(der.end(), (uint8_t *)der_buf + (4096 - der_len),
             (uint8_t *)der_buf + 4096);

  mbedtls_x509write_crt_free(&cert);
  mbedtls_pk_free(&id_pk);

  return der;
}

std::vector<uint8_t> create_id_cert() {
  // signing key
  FILE *signing_secret_key = fopen("../keys/ed25519_signing_secret_key", "rb");

  fseek(signing_secret_key, 0x20, SEEK_SET);

  uint8_t signing_secret_key_raw[64];
  fread(signing_secret_key_raw, 1, 64, signing_secret_key);
  fclose(signing_secret_key);

  std::vector<uint8_t> signing_public_key;
  signing_public_key.insert(signing_public_key.end(), 32, 0);
  ed25519_donna_pubkey(signing_public_key.data(), signing_secret_key_raw);

  // relay id key

  FILE *master_id_secret_key =
      fopen("../keys/ed25519_master_id_secret_key", "rb");

  fseek(master_id_secret_key, 0x20, SEEK_SET);

  std::vector<uint8_t> master_id_secret_key_raw;
  master_id_secret_key_raw.insert(master_id_secret_key_raw.end(), 64, 0);
  fread(master_id_secret_key_raw.data(), 1, 64, master_id_secret_key);
  fclose(master_id_secret_key);

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
  ed25519_donna_sign(signature, cert.data(), cert.size(),
                     master_id_secret_key_raw.data(), id_public_key.data());

  cert.insert(cert.end(), signature, signature + 64);

  return cert;
}

std::vector<uint8_t> create_tls_cert(std::vector<uint8_t> subject) {
  FILE *signing_secret_key = fopen("../keys/ed25519_signing_secret_key", "rb");

  fseek(signing_secret_key, 0x20, SEEK_SET);

  uint8_t secret_key[64];
  fread(secret_key, 1, 64, signing_secret_key);
  fclose(signing_secret_key);

  std::vector<uint8_t> signing_public_key;
  signing_public_key.insert(signing_public_key.end(), 32, 0);

  ed25519_donna_pubkey(signing_public_key.data(), secret_key);

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
  ed25519_donna_sign(signature, cert.data(), cert.size(), secret_key,
                     signing_public_key.data());

  cert.insert(cert.end(), signature, signature + 64);

  return cert;
}

std::optional<LinkKeys> create_link_cert() {
  uint8_t link_public_key[32];
  uint8_t link_secret_key[64];

  ed25519_donna_keygen(link_public_key, link_secret_key);

  FILE *signing_secret_key = fopen("../keys/ed25519_signing_secret_key", "rb");

  fseek(signing_secret_key, 0x20, SEEK_SET);

  uint8_t secret_key[64];
  fread(secret_key, 1, 64, signing_secret_key);
  fclose(signing_secret_key);

  std::vector<uint8_t> signing_public_key;
  signing_public_key.insert(signing_public_key.end(), 32, 0);

  ed25519_donna_pubkey(signing_public_key.data(), secret_key);

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
  ed25519_donna_sign(signature, cert.data(), cert.size(), secret_key,
                     signing_public_key.data());

  // todo rm ts
  int a = ed25519_donna_open(signature, cert.data(), cert.size(),
                             signing_public_key.data());
  if (a < 0) {
    printf("boooo\n");
  }

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

void add_padding_b64(std::string &b64) {
  while (b64.size() % 4 != 0) {
    b64.push_back('=');
  }
}

int main() {
  mbedtls_net_context server_ctx;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_net_init(&server_ctx);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *)"client", 6);

  std::string other_addr_str = "144.208.79.169";
  mbedtls_net_connect(&server_ctx, other_addr_str.c_str(), "9001",
                      MBEDTLS_NET_PROTO_TCP);
  std::string remote_identity_b64 = "mKJ2LWyOc+Bopt4aueqcTP9AW0s";
  std::string remote_ntor_b64 = "Tl1Y0EMy2eUrCO/zLYbO9TtB61m/bZ7v313xemGhNn0";

  // std::string other_addr_str = "127.0.0.1";
  // mbedtls_net_connect(&server_ctx, other_addr_str.c_str(), "9001",
  //                     MBEDTLS_NET_PROTO_TCP);
  // std::string remote_identity_b64 = "JnAOtHlIDaMEWjtDS/es3uRvlP0";
  // std::string remote_ntor_b64 =
  // "q/qPlOcH+iQ6rQn6hY3gr+ekPlz3YY9seXagM9KZIks";

  mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_ssl_setup(&ssl, &conf);

  mbedtls_ssl_set_export_keys_cb(&ssl, tls_key_export_callback, NULL);

  mbedtls_ssl_set_bio(&ssl, &server_ctx, mbedtls_net_send, mbedtls_net_recv,
                      NULL);

  int handshake_ret = mbedtls_ssl_handshake(&ssl);

  while (handshake_ret != 0) {
    if (handshake_ret != MBEDTLS_ERR_SSL_WANT_READ &&
        handshake_ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      printf("error\n");
      break;
    }
  }
  mbedtls_net_set_nonblock(&server_ctx);

  // reduce size format of ip addresses

  struct in_addr other_addr;
  inet_pton(AF_INET, other_addr_str.c_str(), &other_addr);
  uint32_t other_addr_raw = other_addr.s_addr;

  std::string my_addr_str = "127.0.0.1";

  struct in_addr my_addr;
  inet_pton(AF_INET, my_addr_str.c_str(), &my_addr);
  uint32_t my_addr_raw = my_addr.s_addr;

  // read rsa keys
  FILE *signing_secret_key_rsa = fopen("../keys/secret_id_key", "rb");

  fseek(signing_secret_key_rsa, 0, SEEK_END);
  size_t signing_secret_key_rsa_len = ftell(signing_secret_key_rsa);
  fseek(signing_secret_key_rsa, 0, SEEK_SET);

  std::vector<uint8_t> secret_key_rsa;
  secret_key_rsa.insert(secret_key_rsa.end(), signing_secret_key_rsa_len, 0);
  fread(secret_key_rsa.data(), 1, signing_secret_key_rsa_len,
        signing_secret_key_rsa);
  fclose(signing_secret_key_rsa);

  mbedtls_pk_context secret_id_rsa_pk;
  mbedtls_pk_init(&secret_id_rsa_pk);
  mbedtls_pk_parse_key(&secret_id_rsa_pk, secret_key_rsa.data(),
                       secret_key_rsa.size(), NULL, 0, mbedtls_ctr_drbg_random,
                       &ctr_drbg);

  uint8_t der_buf[4096];
  uint8_t *der_buf_cursor = der_buf + 4096;
  int der_len =
      mbedtls_pk_write_pubkey(&der_buf_cursor, der_buf, &secret_id_rsa_pk);

  printf("%s\n", der_buf + (4096 - der_len));

  std::vector<uint8_t> local_KP_relayid_rsa;
  local_KP_relayid_rsa.insert(local_KP_relayid_rsa.end(),
                              (uint8_t *)der_buf + (4096 - der_len),
                              der_buf + 4096);

  uint8_t local_hash_rsa[32];
  mbedtls_sha256(local_KP_relayid_rsa.data(), local_KP_relayid_rsa.size(),
                 local_hash_rsa, false);

  // TODO: refactor parsing keys
  // repeat read the id key because my code is so dry:

  FILE *master_id_secret_key =
      fopen("../keys/ed25519_master_id_secret_key", "rb");

  fseek(master_id_secret_key, 0x20, SEEK_SET);

  std::vector<uint8_t> master_id_secret_key_raw;
  master_id_secret_key_raw.insert(master_id_secret_key_raw.end(), 64, 0);
  fread(master_id_secret_key_raw.data(), 1, 64, master_id_secret_key);
  fclose(master_id_secret_key);

  std::vector<uint8_t> id_public_key;
  id_public_key.insert(id_public_key.end(), 32, 0);

  ed25519_donna_pubkey(id_public_key.data(), master_id_secret_key_raw.data());

  // read ntor key
  FILE *signing_ntor_key = fopen("../keys/secret_onion_key_ntor", "rb");

  fseek(signing_ntor_key, 0x20, SEEK_SET);

  std::vector<uint8_t> ntor_key;
  ntor_key.insert(ntor_key.end(), 64, 0);
  fread(ntor_key.data(), 1, 64, signing_ntor_key);
  fclose(signing_ntor_key);

  // get responder x509
  const mbedtls_x509_crt *responder_cert = mbedtls_ssl_get_peer_cert(&ssl);
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
  mbedtls_ssl_export_keying_material(&ssl, keying_material.data(), 32,
                                     label.c_str(), label.size(),
                                     local_hash_rsa, 32, true);

  // IDENTITY_V_SIGNING
  auto id_cert = create_id_cert();

  // SIGNING_V_TLS_CERT
  auto tls_cert = create_tls_cert(responder_cert_hash);

  // SIGNING_V_LINK_AUTH
  auto link_cert = create_link_cert();

  // RSA_ID_X509
  auto rsa_id_cert = create_rsa_id_cert(&ctr_drbg);

  // RSA_ID_V_IDENTITY
  auto cross_cert = create_cross_cert(&ctr_drbg);

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

  // start the tor connection

  TorConnection connection(
      {{0x04, id_cert},
       {0x06, link_cert->cert},
       /*{0x05, tls_cert},*/
       {0x02, rsa_id_cert},
       {0x07, cross_cert}},
      id_public_key, link_cert->link_secret_key, link_cert->link_public_key,
      my_addr_raw, other_addr_raw, secret_key_rsa, responder_data,
      keying_material, ntor_key, remote_identity_digest, remote_ntor_pub_key);

  set_global_conn(&connection);

  std::vector<uint8_t> send_buffer = {};
  std::vector<uint8_t> initiator_log = {};
  connection.generate_versions_cell(send_buffer);

  FILE *from_me = fopen("from_me.log", "w");
  mbedtls_ssl_write(&ssl, send_buffer.data(), send_buffer.size());
  fwrite(send_buffer.data(), send_buffer.size(), 1, from_me);
  initiator_log.insert(initiator_log.end(), send_buffer.begin(),
                       send_buffer.end());
  fflush(from_me);
  send_buffer.clear();

  std::vector<uint8_t> read_buffer;
  int size;
  FILE *log_file = fopen("out.log", "w");

  std::thread socks_thread(
      [] { setup_socks(TorConnection::create_unix_socket); });
  socks_thread.detach();

  size_t cycles = 0;
  while (true) {
    cycles++;

    connection.step(read_buffer, send_buffer, initiator_log);

    if (!send_buffer.empty()) {

      mbedtls_ssl_write(&ssl, send_buffer.data(), send_buffer.size());

      fwrite(send_buffer.data(), send_buffer.size(), 1, from_me);
      fflush(from_me);
      send_buffer.clear();
    }

    unsigned char buf[256];

    size = mbedtls_ssl_read(&ssl, buf, 256);
    if (size == 0) {
      continue;
    }
    if (size <= 0) {
      if (errno == EAGAIN) {
        continue;
      }
      break;
    }

    read_buffer.insert(read_buffer.end(), buf, buf + size);

    fwrite(buf, size, 1, log_file);
    fflush(log_file);
  }
  fclose(log_file);

  mbedtls_ssl_free(&ssl);
  mbedtls_net_free(&server_ctx);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
}
