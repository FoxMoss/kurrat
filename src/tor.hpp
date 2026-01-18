#pragma once
#include "mbedtls/md.h"
#include <iterator>
#include <mutex>
#include <queue>
#include <unordered_map>
extern "C" {
#include "donna/ed25519_donna_tor.h"
}
#include "mbedtls/base64.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <linux/tls.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/sha1.h>
#include <mbedtls/ssl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <print>
#include <sodium.h>
#include <sodium/crypto_sign.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#define CELL_BODY_LEN 509

class TorConnection {
public:
  static int create_unix_socket(char *addr, uint16_t port, uint16_t stream_id);

  TorConnection(const TorConnection &other)
      : local_KP_relayid_rsa(other.local_KP_relayid_rsa),
        local_KP_relayid_ed(other.local_KP_relayid_ed),
        local_certs(other.local_certs), responder_cert(other.responder_cert),
        keying_material(other.keying_material),
        link_secret_key(other.link_secret_key),
        link_public_key(other.link_public_key), my_addr(other.my_addr),
        other_addr(other.other_addr), secret_ntor(other.secret_ntor),
        remote_identity_digest(other.remote_identity_digest),
        remote_ntor_pub_key(other.remote_ntor_pub_key) {

    mbedtls_pk_init(&rsa_pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)"client", 6);
    psa_crypto_init();
    mbedtls_sha1_init(&forward_sha1_ctx);
    mbedtls_sha1_starts(&forward_sha1_ctx);
    mbedtls_sha1_init(&backward_sha1_ctx);
    mbedtls_sha1_starts(&backward_sha1_ctx);

    ntor_public_key.insert(ntor_public_key.end(), crypto_scalarmult_SCALARBYTES,
                           0);
    crypto_scalarmult_curve25519_base(ntor_public_key.data(),
                                      secret_ntor.data());

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_aes_init(&forward_aes_ctx);
    mbedtls_aes_init(&backward_aes_ctx);
  }

  TorConnection(
      std::vector<std::pair<uint8_t, std::vector<uint8_t>>> local_certs,
      std::vector<uint8_t> local_KP_relayid_ed,
      std::vector<uint8_t> link_secret_key,
      std::vector<uint8_t> link_public_key, uint32_t my_addr,
      uint32_t other_addr, mbedtls_pk_context *rsa_secret_key,
      std::vector<uint8_t> responder_cert, std::vector<uint8_t> keying_material,
      std::vector<uint8_t> secret_ntor,
      std::vector<uint8_t> remote_identity_digest,
      std::vector<uint8_t> remote_ntor_pub_key)
      : local_KP_relayid_ed(local_KP_relayid_ed), local_certs(local_certs),
        responder_cert(responder_cert), keying_material(keying_material),
        link_secret_key(link_secret_key), link_public_key(link_public_key),
        my_addr(htonl(my_addr)), other_addr(htonl(other_addr)),
        secret_ntor(secret_ntor),
        remote_identity_digest(remote_identity_digest),
        remote_ntor_pub_key(remote_ntor_pub_key) {

    mbedtls_pk_init(&rsa_pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)"client", 6);

    uint8_t der_buf[4096];
    uint8_t *der_buf_cursor = der_buf + 4096;
    int der_len =
        mbedtls_pk_write_pubkey(&der_buf_cursor, der_buf, rsa_secret_key);

    local_KP_relayid_rsa.insert(local_KP_relayid_rsa.end(),
                                (uint8_t *)der_buf + (4096 - der_len),
                                der_buf + 4096);
    psa_crypto_init();
    mbedtls_sha1_init(&forward_sha1_ctx);
    mbedtls_sha1_starts(&forward_sha1_ctx);
    mbedtls_sha1_init(&backward_sha1_ctx);
    mbedtls_sha1_starts(&backward_sha1_ctx);

    ntor_public_key.insert(ntor_public_key.end(), crypto_scalarmult_SCALARBYTES,
                           0);
    crypto_scalarmult_curve25519_base(ntor_public_key.data(),
                                      secret_ntor.data());

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_aes_init(&forward_aes_ctx);
    mbedtls_aes_init(&backward_aes_ctx);
  }
  ~TorConnection() {
    mbedtls_ecp_group_free(&grp);

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    if (generated_circuit) {
      mbedtls_mpi_free(&circuit_priv_key);
      mbedtls_ecp_point_free(&circuit_pub_key);
    }

    mbedtls_sha1_free(&forward_sha1_ctx);
    mbedtls_sha1_free(&backward_sha1_ctx);

    mbedtls_aes_free(&forward_aes_ctx);
    mbedtls_aes_free(&backward_aes_ctx);
  }

  void generate_versions_cell(std::vector<uint8_t> &return_buffer) {
    std::vector<uint8_t> data = {};
    uint16_t version_data = htons(3);
    data.insert(data.end(), (uint8_t *)&version_data,
                (uint8_t *)&version_data + sizeof(uint16_t));
    generate_cell_variable(return_buffer, 0, 7, data);
  }

  bool sent_auth = false;
  std::vector<uint8_t> responder_log;
  std::mutex during_step;
  void step(std::vector<uint8_t> &return_buffer,
            std::vector<uint8_t> &send_buffer,
            std::vector<uint8_t> &initiator_log) {

    std::lock_guard<std::mutex> guard(during_step);

    while (parse_cell(return_buffer, send_buffer, initiator_log)) {
    }

    send_buffer.insert(send_buffer.end(), additional_send_buffer.begin(),
                       additional_send_buffer.end());
    additional_send_buffer.clear();

    for (auto stream : stream_map) {

      if (!stream.second.file_descriptor_pipe.has_value() ||
          my_global_sent_window <= 0 || stream.second.stream_sent_window <= 0)
        continue;

      std::vector<uint8_t> data;
      data.insert(data.end(), 256, 0);
      int ret_size = read(stream.second.file_descriptor_pipe.value(),
                          data.data(), data.size());

      if (ret_size <= 0)
        continue;

      data.erase(data.begin() + ret_size, data.end());

      generate_data_relay(send_buffer, data, global_circuit_id, stream.first);
    }
  }

  bool parse_cell(std::vector<uint8_t> &return_buffer,
                  std::vector<uint8_t> &send_buffer,
                  std::vector<uint8_t> &initiator_log) {

    if (return_buffer.empty()) {
      return false;
    }

    uint64_t cursor = 0;
    auto circ_id = parse_uint16(return_buffer, cursor);
    if (!circ_id.has_value()) {
      return false;
    }
    auto command = parse_uint8(return_buffer, cursor);
    if (!command.has_value()) {
      return false;
    }

    if (command.value() == 7 || command.value() >= 128) { // variable length

      auto length = parse_uint16(return_buffer, cursor);
      if (!length.has_value()) {
        return false;
      }

      uint16_t real_length = ntohs(length.value());

      auto payload = parse_fixed_buffer(return_buffer, cursor, real_length);
      if (!payload.has_value()) {
        return false;
      }

      switch (command.value()) {
      case 7: {
        // cool we dont really gaf its their job to close the connection
        break;
      }
      case 129: {

        auto cert_buffer = payload.value();
        uint64_t cert_cursor = 0;

        auto certs = parse_cert(cert_buffer, cert_cursor);
        if (!certs.has_value()) {
          printf("NON-FATAL: Certs reading failed\n");
        }
        break;
      }

      case 130: {
        auto auth_buffer = payload.value();
        uint64_t auth_cursor = 0;

        auto auth = parse_auth(auth_buffer, auth_cursor);
        if (!auth.has_value()) {
          printf("NON-FATAL: Auth challenge reading failed\n");
        }

        break;
      }
      }
    } else {
      auto payload = parse_fixed_buffer(return_buffer, cursor, CELL_BODY_LEN);
      if (!payload.has_value()) {
        return false;
      }

      switch (command.value()) {
      case 8: {
        // we also dont gaf about the incoming netinfo
        // but we should get ready to send out own packets!

        if (!sent_auth) {
          generate_cert_cell(send_buffer);
          initiator_log.insert(initiator_log.end(), send_buffer.begin(),
                               send_buffer.end());

          generate_authenticate_cell(send_buffer, initiator_log);
          generate_netinfo_cell(send_buffer);

          generate_create2_cell(send_buffer, global_circuit_id);
          // generate_create2_cell(send_buffer, 0x8001);
        }

        break;
      }
      case 11: {
        auto created_buffer = payload.value();
        uint64_t created_cursor = 0;
        parse_created(created_buffer, created_cursor);

        // generate_begin_relay_cell(send_buffer, global_circuit_id, 22,
        //                           "205.185.125.167:443", 0);
        break;
      }
      case 3: {

        auto relay_buffer = payload.value();
        uint64_t relay_cursor = 0;

        parse_relay(relay_buffer, ntohs(circ_id.value()), relay_cursor,
                    send_buffer);
        break;
      }
      case 4: {
        auto destroy_buffer = payload.value();
        uint64_t destroy_cursor = 0;

        parse_destroy(destroy_buffer, destroy_cursor);
        break;
      }
      }
    }

    if (!sent_auth) {
      responder_log.insert(responder_log.end(), return_buffer.begin(),
                           return_buffer.begin() + cursor);

      initiator_log.insert(initiator_log.end(), send_buffer.begin(),
                           send_buffer.end());
    }
    return_buffer.erase(return_buffer.begin(), return_buffer.begin() + cursor);

    // we need it for the log but then we can stop logging
    if (command.value() == 8) {
      sent_auth = true;
    }

    return true;
  }

private:
  std::vector<uint8_t> additional_send_buffer = {};

  uint16_t global_circuit_id = 0b0000000000000010;

  void generate_cell_fixed(std::vector<uint8_t> &return_buffer,
                           uint16_t circuit_id, uint8_t command,
                           std::vector<uint8_t> &data) {

    uint16_t circuit_id_converted = htons(circuit_id);
    return_buffer.insert(return_buffer.end(), (uint8_t *)&circuit_id_converted,
                         (uint8_t *)&circuit_id_converted + sizeof(uint16_t));
    return_buffer.push_back(command);

    uint16_t padding = CELL_BODY_LEN - data.size();
    return_buffer.insert(return_buffer.end(), data.begin(), data.end());
    return_buffer.insert(return_buffer.end(), padding, 0);
  }
  void generate_cell_variable(std::vector<uint8_t> &return_buffer,
                              uint16_t circuit_id, uint8_t command,
                              std::vector<uint8_t> &data) {

    uint16_t circuit_id_converted = htons(circuit_id);
    return_buffer.insert(return_buffer.end(), (uint8_t *)&circuit_id_converted,
                         (uint8_t *)&circuit_id_converted + sizeof(uint16_t));
    return_buffer.push_back(command);

    uint16_t data_len = htons((uint16_t)data.size());

    return_buffer.insert(return_buffer.end(), (uint8_t *)&data_len,
                         (uint8_t *)&data_len + sizeof(uint16_t));
    return_buffer.insert(return_buffer.end(), data.begin(), data.end());
  }

  std::optional<uint16_t> parse_uint16(std::vector<uint8_t> &return_buffer,
                                       uint64_t &cursor) {
    if (return_buffer.size() < cursor + sizeof(uint16_t)) {
      return {};
    }

    uint16_t out;
    memcpy(&out, return_buffer.data() + cursor, sizeof(uint16_t));
    cursor += sizeof(uint16_t);
    return out;
  }
  std::optional<uint8_t> parse_uint8(std::vector<uint8_t> &return_buffer,
                                     uint64_t &cursor) {
    if (return_buffer.size() < cursor + sizeof(uint8_t)) {
      return {};
    }

    uint8_t out;
    memcpy(&out, return_buffer.data() + cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    return out;
  }
  std::optional<std::vector<uint8_t>>
  parse_fixed_buffer(std::vector<uint8_t> &return_buffer, uint64_t &cursor,
                     uint64_t size) {
    if (return_buffer.size() < cursor + size) {
      return {};
    }

    std::vector<uint8_t> out;

    out.insert(out.end(), return_buffer.begin() + cursor,
               return_buffer.begin() + cursor + size);

    cursor += size;
    return out;
  }

  enum CertType {
    TLS_LINK_X509 = 0x01,
    RSA_ID_X509 = 0x02,
    LINK_AUTH_X509 = 0x03,
    IDENTITY_V_SIGNING = 0x04,
    SIGNING_V_TLS_CERT = 0x05,
    SIGNING_V_LINK_AUTH = 0x06,
    RSA_ID_V_IDENTITY = 0x07,
    BLINDED_ID_V_SIGNING = 0x08,
    HS_IP_V_SIGNING = 0x09,
    NTOR_CC_IDENTITY = 0x0A,
    HS_IP_CC_SIGNING = 0x0B,
  };

  std::vector<uint8_t> remote_KP_relayid_rsa;
  std::vector<uint8_t> local_KP_relayid_rsa;
  std::vector<uint8_t> local_KP_relayid_ed;
  std::vector<uint8_t> remote_KP_relayid_ed;
  void parse_x509_cert(std::vector<uint8_t> &cert_rsa_buffer) {
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_parse(&crt, cert_rsa_buffer.data(),
                           cert_rsa_buffer.size());
    uint8_t der_buf[4096];
    uint8_t *der_buf_cursor = der_buf + 4096;
    // tf do we write to the end???
    int der_len = mbedtls_pk_write_pubkey(&der_buf_cursor, der_buf, &crt.pk);
    mbedtls_x509_crt_free(&crt);

    remote_KP_relayid_rsa.insert(remote_KP_relayid_rsa.end(),
                                 der_buf + 4096 - der_len, der_buf + 4096);
  }

  void parse_rsa_cert(std::vector<uint8_t> &cert_rsa_buffer) {
    remote_KP_relayid_ed.insert(remote_KP_relayid_ed.end(),
                                cert_rsa_buffer.begin(),
                                cert_rsa_buffer.begin() + 32);
  }

  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> remote_certs;
  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> local_certs;
  std::optional<bool> parse_cert(std::vector<uint8_t> &cert_buffer,
                                 uint64_t &cursor) {
    auto count = parse_uint8(cert_buffer, cursor);
    if (!count.has_value())
      return {};

    for (uint64_t i = 0; i < count; i++) {
      auto cert_type = parse_uint8(cert_buffer, cursor);
      if (!cert_type.has_value())
        return {};

      auto cert_len = parse_uint16(cert_buffer, cursor);
      if (!cert_len.has_value())
        return {};

      auto cert =
          parse_fixed_buffer(cert_buffer, cursor, ntohs(cert_len.value()));
      if (!cert.has_value())
        return {};

      remote_certs.push_back({cert_type.value(), cert.value()});

      switch ((CertType)cert_type.value()) {
      case TLS_LINK_X509:
        break;
      case RSA_ID_X509:
        parse_x509_cert(cert.value());

        break;
      case LINK_AUTH_X509:
        break;
      case IDENTITY_V_SIGNING:
        break;
      case SIGNING_V_TLS_CERT:
        break;
      case SIGNING_V_LINK_AUTH:
        break;
      case RSA_ID_V_IDENTITY:
        parse_rsa_cert(cert.value());
        break;
      case BLINDED_ID_V_SIGNING:
        break;
      case HS_IP_V_SIGNING:
        break;
      case NTOR_CC_IDENTITY:
        break;
      case HS_IP_CC_SIGNING:
        break;
      }
    }

    return true;
  }

  std::vector<std::vector<uint8_t>> auth_challenges;
  std::optional<bool> parse_auth(std::vector<uint8_t> &auth_buffer,
                                 uint64_t &cursor) {

    auto challenge = parse_fixed_buffer(auth_buffer, cursor, 32);
    if (!challenge.has_value()) {
      return {};
    }

    auto method_count = parse_uint16(auth_buffer, cursor);
    if (!method_count.has_value()) {
      return {};
    }

    bool found_Ed25519_SHA256_RFC5705 = false;

    for (uint64_t i = 0; i < ntohs(method_count.value()); i++) {

      auto method = parse_uint16(auth_buffer, cursor);
      if (!method.has_value()) {
        return {};
      }

      if (ntohs(method.value()) == 0x03) {
        found_Ed25519_SHA256_RFC5705 = true;
      }
    }
    if (!found_Ed25519_SHA256_RFC5705) {
      return {}; // everything else is unused lmao so we just care about this
                 // one
    }

    auth_challenges.push_back(challenge.value());

    return true;
  }

  void parse_destroy(std::vector<uint8_t> &destroy_buffer, uint64_t &cursor) {
    auto destroy_reason = parse_uint8(destroy_buffer, cursor);
    printf("destroyed with reason, %i\n", destroy_reason.value());
    connected_to_exit = false;
    printf("disconnected from exit node.\n");
  }

  void parse_created(std::vector<uint8_t> &created_buffer, uint64_t &cursor) {
    parse_uint16(created_buffer, cursor); // hanshake len

    auto server_circuit_key_public_raw =
        parse_fixed_buffer(created_buffer, cursor, 32);

    mbedtls_mpi circuit_shared_secret;

    mbedtls_ecp_point server_circuit_key_public;
    mbedtls_ecp_point_init(&server_circuit_key_public);

    mbedtls_ecp_point_read_binary(&grp, &server_circuit_key_public,
                                  server_circuit_key_public_raw->data(),
                                  server_circuit_key_public_raw->size());

    mbedtls_ecdh_compute_shared(&grp, &circuit_shared_secret,
                                &server_circuit_key_public, &circuit_priv_key,
                                mbedtls_ctr_drbg_random, &ctr_drbg);

    std::vector<uint8_t> circuit_shared_secret_bytes;
    circuit_shared_secret_bytes.insert(circuit_shared_secret_bytes.end(), 32,
                                       0);
    mbedtls_mpi_write_binary(&circuit_shared_secret,
                             circuit_shared_secret_bytes.data(), 32);

    mbedtls_mpi ntor_shared_secret;

    mbedtls_ecp_point server_ntor_key_public;
    mbedtls_ecp_point_init(&server_ntor_key_public);

    mbedtls_ecp_point_read_binary(&grp, &server_ntor_key_public,
                                  remote_ntor_pub_key.data(),
                                  remote_ntor_pub_key.size());

    mbedtls_ecdh_compute_shared(&grp, &ntor_shared_secret,
                                &server_ntor_key_public, &circuit_priv_key,
                                mbedtls_ctr_drbg_random, &ctr_drbg);

    std::vector<uint8_t> ntor_shared_secret_bytes;
    ntor_shared_secret_bytes.insert(ntor_shared_secret_bytes.end(), 32, 0);
    mbedtls_mpi_write_binary(&ntor_shared_secret,
                             ntor_shared_secret_bytes.data(), 32);

    // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    std::vector<uint8_t> secret_input;

    // why is it reversed??
    // no idea, little endian issue maybe?
    secret_input.insert(
        secret_input.end(),
        std::reverse_iterator(circuit_shared_secret_bytes.end()),
        std::reverse_iterator(circuit_shared_secret_bytes.begin()));

    secret_input.insert(
        secret_input.end(),
        std::reverse_iterator(ntor_shared_secret_bytes.end()),
        std::reverse_iterator(ntor_shared_secret_bytes.begin()));

    secret_input.insert(secret_input.end(), remote_identity_digest.begin(),
                        remote_identity_digest.end());

    secret_input.insert(secret_input.end(), remote_ntor_pub_key.begin(),
                        remote_ntor_pub_key.end());

    std::vector<uint8_t> circuit_pub_key_bytes;
    circuit_pub_key_bytes.insert(circuit_pub_key_bytes.end(), 32, 0);

    size_t olen = 0;
    mbedtls_ecp_point_write_binary(
        &grp, &circuit_pub_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
        circuit_pub_key_bytes.data(), circuit_pub_key_bytes.size());

    secret_input.insert(secret_input.end(), circuit_pub_key_bytes.begin(),
                        circuit_pub_key_bytes.end());

    secret_input.insert(secret_input.end(),
                        server_circuit_key_public_raw->begin(),
                        server_circuit_key_public_raw->end());

    std::string proto_id = "ntor-curve25519-sha256-1";
    secret_input.insert(secret_input.end(), proto_id.begin(), proto_id.end());

    std::string key_extract = proto_id + ":key_extract";

    std::vector<uint8_t> key_seed;
    key_seed.insert(key_seed.end(), 32, 0);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    (const uint8_t *)key_extract.data(), key_extract.size(),
                    secret_input.data(), secret_input.size(), key_seed.data());

    mbedtls_mpi_free(&circuit_shared_secret);
    mbedtls_mpi_free(&ntor_shared_secret);

    mbedtls_ecp_point_free(&server_circuit_key_public);
    mbedtls_ecp_point_free(&server_ntor_key_public);

    // generate material
    std::string key_expand = proto_id + ":key_expand";
    std::vector<uint8_t> key_expand1;
    key_expand1.insert(key_expand1.end(), key_expand.begin(), key_expand.end());
    key_expand1.push_back(1);

    auto hash_func = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    auto key_size = 32;
#define key_type uint8_t

    // K1
    std::vector<key_type> key1;
    key1.insert(key1.end(), key_size, 0);
    mbedtls_md_hmac(hash_func, key_seed.data(), key_seed.size(),
                    key_expand1.data(), key_expand1.size(), key1.data());

    // K2
    std::vector<key_type> key_expand2;
    key_expand2.insert(key_expand2.end(), key1.begin(), key1.end());
    key_expand2.insert(key_expand2.end(), key_expand.begin(), key_expand.end());
    key_expand2.push_back(2);

    std::vector<key_type> key2;
    key2.insert(key2.end(), key_size, 0);
    mbedtls_md_hmac(hash_func, key_seed.data(), key_seed.size(),
                    key_expand2.data(), key_expand2.size(), key2.data());

    // K3
    std::vector<key_type> key_expand3;
    key_expand3.insert(key_expand3.end(), key2.begin(), key2.end());
    key_expand3.insert(key_expand3.end(), key_expand.begin(), key_expand.end());
    key_expand3.push_back(3);

    std::vector<key_type> key3;
    key3.insert(key3.end(), key_size, 0);
    mbedtls_md_hmac(hash_func, key_seed.data(), key_seed.size(),
                    key_expand3.data(), key_expand3.size(), key3.data());

    std::vector<uint8_t> combined_key;
    combined_key.insert(combined_key.end(), key1.begin(), key1.end());
    combined_key.insert(combined_key.end(), key2.begin(), key2.end());
    combined_key.insert(combined_key.end(), key3.begin(), key3.end());

    mbedtls_sha1_update(&forward_sha1_ctx, combined_key.data(), 20);
    mbedtls_sha1_update(&backward_sha1_ctx, combined_key.data() + 20, 20);

    forward_encryption_key = std::vector<uint8_t>{};
    forward_encryption_key->insert(forward_encryption_key->end(),
                                   combined_key.begin() + 20 + 20,
                                   combined_key.begin() + 20 + 20 + 16);

    mbedtls_aes_setkey_enc(&forward_aes_ctx, forward_encryption_key->data(),
                           128);

    backward_encryption_key = std::vector<uint8_t>{};
    backward_encryption_key->insert(backward_encryption_key->end(),
                                    combined_key.begin() + 20 + 20 + 16,
                                    combined_key.begin() + 20 + 20 + 16 + 16);
    mbedtls_aes_setkey_enc(&backward_aes_ctx, backward_encryption_key->data(),
                           128);
  }

  struct TorStream {
    bool connected = false;
    std::optional<int> file_descriptor_pipe;
    ssize_t stream_sent_window = 500;
    ssize_t stream_recived_window = 0;
  };
  ssize_t my_global_sent_window = 1000; // 1000 if no circwindow is give
  ssize_t my_global_recived_window = 0;

  std::unordered_map<uint16_t, TorStream> stream_map;
  void generate_begin_relay_cell(std::vector<uint8_t> &send_buffer,
                                 uint16_t circuit_id, uint16_t stream_id,
                                 std::string addrport, uint32_t flags) {
    std::vector<uint8_t> data;
    data.insert(data.end(), addrport.begin(), addrport.end());
    data.push_back(0);

    flags = htonl(flags);
    data.insert(data.end(), (uint8_t *)&flags,
                (uint8_t *)&flags + sizeof(uint32_t));

    stream_map[stream_id] = {};

    generate_relay_cell(send_buffer, 1, circuit_id, stream_id, data);
  }

  bool parse_relay(std::vector<uint8_t> &relay_buffer, uint16_t circuit_id,
                   uint64_t &cursor, std::vector<uint8_t> &send_buffer);

  bool parse_end_relay(std::vector<uint8_t> &end_buffer, uint64_t &cursor);

  bool parse_data_relay(std::vector<uint8_t> &end_buffer, uint16_t circuit_id,
                        uint16_t stream_id, std::vector<uint8_t> &send_buffer);

  bool generate_send_me_relay(uint16_t circuit_id, uint16_t stream_id,
                              std::vector<uint8_t> &send_buffer);

  bool generate_data_relay(std::vector<uint8_t> &send_buffer,
                           std::vector<uint8_t> data, uint16_t circuit_id,
                           uint16_t stream_id);

  std::optional<std::vector<uint8_t>> forward_encryption_key;
  std::optional<std::vector<uint8_t>> backward_encryption_key;
  uint8_t forward_stream_block[16] = {};
  uint8_t forward_stream_iv[16] = {};
  uint8_t backward_stream_block[16] = {};
  uint8_t backward_stream_iv[16] = {};

  mbedtls_pk_context rsa_pk;
  std::vector<uint8_t> responder_cert;
  std::vector<uint8_t> keying_material;
  std::vector<uint8_t> link_secret_key;
  std::vector<uint8_t> link_public_key;
  void generate_authenticate_cell(std::vector<uint8_t> &send_buffer,
                                  std::vector<uint8_t> &initiator_log) {
    for (auto challenge : auth_challenges) {
      std::vector<uint8_t> data = {};
      uint16_t auth_type = 0x03;
      auth_type = htons(auth_type);

      std::vector<uint8_t> auth_buffer;
      std::string auth_type_str = "AUTH0003";
      auth_buffer.insert(auth_buffer.end(), auth_type_str.begin(),
                         auth_type_str.end());

      // rsa
      uint8_t local_hash_rsa[32];
      mbedtls_sha256(local_KP_relayid_rsa.data(), local_KP_relayid_rsa.size(),
                     local_hash_rsa, false);

      auth_buffer.insert(auth_buffer.end(), local_hash_rsa,
                         local_hash_rsa + 32);

      uint8_t remote_hash_rsa[32];
      mbedtls_sha256(remote_KP_relayid_rsa.data(), remote_KP_relayid_rsa.size(),
                     remote_hash_rsa, false);

      auth_buffer.insert(auth_buffer.end(), remote_hash_rsa,
                         remote_hash_rsa + 32);

      // ed time!
      auth_buffer.insert(auth_buffer.end(), local_KP_relayid_ed.begin(),
                         local_KP_relayid_ed.end());

      auth_buffer.insert(auth_buffer.end(), remote_KP_relayid_ed.begin(),
                         remote_KP_relayid_ed.end());

      // slog
      uint8_t remote_log_hash[32];
      mbedtls_sha256(responder_log.data(), responder_log.size(),
                     remote_log_hash, false);
      auth_buffer.insert(auth_buffer.end(), remote_log_hash,
                         remote_log_hash + 32);
      // clog
      uint8_t local_log_hash[32];
      mbedtls_sha256(initiator_log.data(), initiator_log.size(), local_log_hash,
                     false);
      auth_buffer.insert(auth_buffer.end(), local_log_hash,
                         local_log_hash + 32);

      // tls here
      uint8_t scert_hash[32];
      mbedtls_sha256(responder_cert.data(), responder_cert.size(), scert_hash,
                     false);
      auth_buffer.insert(auth_buffer.end(), scert_hash, scert_hash + 32);

      // material
      // TODO bad
      auth_buffer.insert(auth_buffer.end(), keying_material.begin(),
                         keying_material.end());

      std::vector<uint8_t> random_buf;
      random_buf.insert(random_buf.end(), 24, 0);
      psa_generate_random(random_buf.data(), random_buf.size());

      auth_buffer.insert(auth_buffer.end(), random_buf.begin(),
                         random_buf.end());

      unsigned char signature[64];
      ed25519_donna_sign(signature, auth_buffer.data(), auth_buffer.size(),
                         link_secret_key.data(), link_public_key.data());

      auth_buffer.insert(auth_buffer.end(), signature, signature + 64);

      // put in buffer
      uint16_t auth_length = auth_buffer.size();
      auth_length = htons(auth_length);
      data.insert(data.end(), (uint8_t *)&auth_type,
                  (uint8_t *)&auth_type + sizeof(uint16_t));
      data.insert(data.end(), (uint8_t *)&auth_length,
                  (uint8_t *)&auth_length + sizeof(uint16_t));
      data.insert(data.end(), auth_buffer.begin(), auth_buffer.end());

      generate_cell_variable(send_buffer, 0, 131, data);

      connected_to_exit = true;
      printf("connected to exit node and ready to accept\n");
    }

    auth_challenges.clear();
  }
  bool connected_to_exit = false;

  void generate_cert_cell(std::vector<uint8_t> &send_buffer) {
    std::vector<uint8_t> data = {};
    data.push_back(local_certs.size()); // cert count

    for (auto cert : local_certs) {
      data.push_back(cert.first);

      uint16_t cert_len = htons(cert.second.size());

      data.insert(data.end(), (uint8_t *)&cert_len,
                  (uint8_t *)&cert_len + sizeof(uint16_t));

      data.insert(data.end(), cert.second.begin(), cert.second.end());
    }

    generate_cell_variable(send_buffer, 0, 129, data);
  }

  uint32_t my_addr, other_addr;
  // https://torspec-12e191.pages.torproject.net/tor-spec/negotiating-channels.html#NETINFO-cells
  void generate_netinfo_cell(std::vector<uint8_t> &send_buffer) {
    uint32_t epoch = (uint32_t)time(NULL);
    epoch = htonl(epoch);

    std::vector<uint8_t> data = {};
    data.insert(data.end(), (uint8_t *)&epoch,
                (uint8_t *)&epoch + sizeof(uint32_t));

    // other addr
    uint32_t other_addr_flipped = htonl(other_addr);
    data.push_back(0x04); // ipv4
    data.push_back(sizeof(uint32_t));
    data.insert(data.end(), (uint8_t *)&other_addr_flipped,
                (uint8_t *)&other_addr_flipped + sizeof(uint32_t));

    // my addrs
    data.push_back(1); // i have one address

    uint32_t my_addr_flipped = htonl(my_addr);
    data.push_back(0x04); // ipv4
    data.push_back(sizeof(uint32_t));
    data.insert(data.end(), (uint8_t *)&my_addr_flipped,
                (uint8_t *)&my_addr_flipped + sizeof(uint32_t));

    generate_cell_fixed(send_buffer, 0, 8, data);
  }

  bool generated_circuit = false;
  mbedtls_mpi circuit_priv_key;
  mbedtls_ecp_point circuit_pub_key;

  mbedtls_ecp_group grp;

  std::vector<uint8_t> secret_ntor;
  std::vector<uint8_t> ntor_public_key;

  std::vector<uint8_t> remote_identity_digest;
  std::vector<uint8_t> remote_ntor_pub_key;
  void generate_create2_cell(std::vector<uint8_t> &return_buffer,
                             uint16_t circuit_id) {
    std::vector<uint8_t> data = {};
    uint16_t htype = htons(0x0002);
    data.insert(data.end(), (uint8_t *)&htype,
                (uint8_t *)&htype + sizeof(uint16_t));

    std::vector<uint8_t> handshake_data = {};

    // identity
    handshake_data.insert(handshake_data.end(), remote_identity_digest.begin(),
                          remote_identity_digest.end());

    // ntor
    handshake_data.insert(handshake_data.end(), remote_ntor_pub_key.begin(),
                          remote_ntor_pub_key.end());

    // new pub key

    mbedtls_mpi temp_priv_key;
    mbedtls_mpi_init(&temp_priv_key);
    mbedtls_ecp_point temp_pub_key_raw;
    mbedtls_ecp_point_init(&temp_pub_key_raw);
    mbedtls_ecdh_gen_public(&grp, &temp_priv_key, &temp_pub_key_raw,
                            mbedtls_ctr_drbg_random, &ctr_drbg);

    generated_circuit = true;
    circuit_priv_key = temp_priv_key;
    circuit_pub_key = temp_pub_key_raw;

    std::vector<uint8_t> temp_pub_key;
    temp_pub_key.insert(temp_pub_key.end(), 32, 0);
    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&grp, &temp_pub_key_raw,
                                   MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                   temp_pub_key.data(), 32);

    handshake_data.insert(handshake_data.end(), temp_pub_key.begin(),
                          temp_pub_key.end());

    uint16_t hlength = htons(handshake_data.size());
    data.insert(data.end(), (uint8_t *)&hlength,
                (uint8_t *)&hlength + sizeof(uint16_t));
    data.insert(data.end(), handshake_data.begin(), handshake_data.end());

    generate_cell_fixed(return_buffer, circuit_id, 10, data);
  }

  mbedtls_sha1_context forward_sha1_ctx;
  mbedtls_sha1_context backward_sha1_ctx;

  mbedtls_aes_context forward_aes_ctx;
  mbedtls_aes_context backward_aes_ctx;
  size_t forward_stream_offset = 0;
  size_t backward_stream_offset = 0;

  // A NOTE:
  // intiatior -> noted == out ==  forward
  // intiatior <- noted == in  ==  backward

  // relay things
  void generate_relay_cell(std::vector<uint8_t> &send_buffer,
                           uint8_t relay_command, uint16_t circuit_id,
                           uint16_t stream_id,
                           std::vector<uint8_t> command_data) {

    std::vector<uint8_t> data = {};

    data.push_back(relay_command);
    data.insert(data.end(), 2,
                0); // two bytes for recognized
    stream_id = htons(stream_id);
    data.insert(data.end(), (uint8_t *)&stream_id,
                (uint8_t *)&stream_id + sizeof(uint16_t));

    data.insert(data.end(), 4,
                0); // digest, we need to calculate this after the cell

    uint16_t length = htons(command_data.size());

    // buffer should be smaller than CELL_BODY_LEN - 11
    data.insert(data.end(), (uint8_t *)&length,
                (uint8_t *)&length + sizeof(uint16_t));

    data.insert(data.end(), command_data.begin(), command_data.end());

    ssize_t padding_len = CELL_BODY_LEN - 11 - command_data.size();
    if (padding_len < 0) {
      // pray we dont have to handle this case
      printf("WARN: buffer to big for relay cell\n");
    }

    data.insert(data.end(), padding_len, 0);

    if (!forward_encryption_key.has_value()) {
      printf("error: cannot crypto\n");
      return;
    }

    if (data.size() != 509) {
      printf("dropping payload of wrong size\n");
      return;
    }

    mbedtls_sha1_update(&forward_sha1_ctx, data.data(), data.size());

    uint8_t digest_full[20] = {};

    mbedtls_sha1_context old_ctx;

    // make a new sha1 instance because we cant continusiously make hashes
    mbedtls_sha1_init(&old_ctx);
    mbedtls_sha1_clone(&old_ctx, &forward_sha1_ctx);

    mbedtls_sha1_finish(&old_ctx, digest_full);
    mbedtls_sha1_free(&old_ctx);

    memcpy(data.data() + 5, digest_full, 4);

    std::vector<uint8_t> encrypted_data;
    encrypted_data.insert(encrypted_data.end(), data.size(), 0);

    mbedtls_aes_crypt_ctr(&forward_aes_ctx, data.size(), &forward_stream_offset,
                          forward_stream_iv, forward_stream_block,
                          (const uint8_t *)data.data(), encrypted_data.data());

    generate_cell_fixed(send_buffer, circuit_id, 3, encrypted_data);
  }

  // crypto bs
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
};

void set_global_conn(TorConnection *c_tor_connection);

extern "C" {
int setup_socks(int (*make_connection)(char *addr, uint16_t port,
                                       uint16_t stream_id));
}
