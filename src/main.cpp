#include "mbedtls/x509.h"
#include "tor.hpp"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
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
#include <utility>
#include <vector>

void tls_key_export_callback(void *p_expkey, mbedtls_ssl_key_export_type type,
                             const unsigned char *secret, size_t secret_len,
                             const unsigned char client_random[32],
                             const unsigned char server_random[32],
                             mbedtls_tls_prf_types tls_prf_type) {

  static FILE *keylog_file;
  if (keylog_file == nullptr) {
    keylog_file = fopen("sslkeylog.txt", "w");
    return;
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

std::optional<LinkKeys> create_link_cert() {
  uint8_t link_public_key[32];
  uint8_t link_secret_key[64];

  crypto_sign_keypair(link_public_key, link_secret_key);

  FILE *signing_secret_key = fopen("../keys/ed25519_signing_secret_key", "rb");

  fseek(signing_secret_key, 0x20, SEEK_SET);

  uint8_t secret_key[64];
  fread(secret_key, 1, 64, signing_secret_key);
  fclose(signing_secret_key);

  std::vector<uint8_t> cert;
  cert.push_back(1); // version
  cert.push_back(
      0x06); // Ed25519 authentication key signed with ed25519 signing key

  uint32_t expiration =
      (time(NULL) + 86400) / (3600); // this impl will stop working in 2030
  expiration = htonl(expiration);
  cert.insert(cert.end(), (uint8_t *)&expiration,
              (uint8_t *)&expiration + sizeof(uint32_t));

  cert.push_back(0x01); // certified ed25519
  cert.insert(cert.end(), link_public_key, link_public_key + 32);

  cert.push_back(0x00); // no extensions

  unsigned char signature[crypto_sign_BYTES];
  crypto_sign_detached(signature, NULL, cert.data(), cert.size(), secret_key);

  cert.insert(cert.end(), signature, signature + crypto_sign_BYTES);

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

  mbedtls_net_connect(&server_ctx, "23.191.200.26", "443",
                      MBEDTLS_NET_PROTO_TCP);

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

  // generate auth cert now

  if (sodium_init() == -1) {
    printf("FATAL ERROR: Sodium init failed \n");
    return -1;
  }

  auto cert = create_link_cert();

  // reduce size format of ip addresses
  std::string other_addr_str = "23.191.200.26";

  struct in_addr other_addr;
  inet_pton(AF_INET, other_addr_str.c_str(), &other_addr);
  uint32_t other_addr_raw = other_addr.s_addr;

  std::string my_addr_str = "205.185.125.167";

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

  // read secret id key (again)
  FILE *signing_secret_key = fopen("../keys/ed25519_signing_secret_key", "rb");

  fseek(signing_secret_key, 0x20, SEEK_SET);

  std::vector<uint8_t> secret_key;
  secret_key.insert(secret_key.end(), 64, 0);
  fread(secret_key.data(), 1, 64, signing_secret_key);
  fclose(signing_secret_key);

  std::vector<uint8_t> public_key;
  public_key.insert(public_key.end(), crypto_sign_PUBLICKEYBYTES, 0);
  crypto_sign_ed25519_sk_to_pk(public_key.data(), secret_key.data());

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

  // keying_material
  std::vector<uint8_t> keying_material;
  keying_material.insert(keying_material.end(), 32, 0);
  std::string label = "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003";
  mbedtls_ssl_export_keying_material(
      &ssl, keying_material.data(), 32, label.c_str(), label.size(),
      public_key.data(), public_key.size(), true);

  // start the tor connection

  TorConnection connection(cert->cert, public_key, cert->link_secret_key,
                           cert->link_public_key, my_addr_raw, other_addr_raw,
                           secret_key_rsa, responder_data, keying_material,
                           ntor_key);

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
  while (true) {
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

    printf("read! %i \n", size);

    read_buffer.insert(read_buffer.end(), buf, buf + size);
    connection.parse_cell(read_buffer, send_buffer, initiator_log);

    if (!send_buffer.empty()) {

      printf("writing! %zu \n", send_buffer.size());
      mbedtls_ssl_write(&ssl, send_buffer.data(), send_buffer.size());

      fwrite(send_buffer.data(), send_buffer.size(), 1, from_me);
      fflush(from_me);
      send_buffer.clear();
    }

    fwrite(buf, size, 1, log_file);
    fflush(log_file);
  }
  fclose(log_file);

  mbedtls_ssl_free(&ssl);
  mbedtls_net_free(&server_ctx);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
}
