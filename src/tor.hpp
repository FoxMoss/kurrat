#pragma once
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
  TorConnection(std::vector<uint8_t> my_cert,
                std::vector<uint8_t> local_KP_relayid_ed,
                std::vector<uint8_t> link_secret_key,
                std::vector<uint8_t> link_public_key, uint32_t my_addr,
                uint32_t other_addr, std::vector<uint8_t> rsa_secret_key,
                std::vector<uint8_t> responder_cert,
                std::vector<uint8_t> keying_material,
                std::vector<uint8_t> secret_ntor)
      : local_KP_relayid_ed(local_KP_relayid_ed),
        responder_cert(responder_cert), link_secret_key(link_secret_key),
        link_public_key(link_public_key), my_addr(htonl(my_addr)),
        other_addr(htonl(other_addr)), secret_ntor(secret_ntor) {
    local_certs.push_back({0x06, my_cert});

    mbedtls_pk_init(&rsa_pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)"client", 6);

    mbedtls_pk_parse_key(&rsa_pk, rsa_secret_key.data(), rsa_secret_key.size(),
                         NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);

    uint8_t der_buf[4096];
    int der_len =
        mbedtls_pk_write_pubkey_der(&rsa_pk, der_buf, sizeof(der_buf));

    printf("%s\n", der_buf + (4096 - der_len));

    local_KP_relayid_rsa.insert(local_KP_relayid_rsa.end(),
                                (uint8_t *)der_buf + (4096 - der_len),
                                der_buf + 4096);
    psa_crypto_init();
    mbedtls_sha1_init(&sha1_ctx);

    ntor_public_key.insert(ntor_public_key.end(), crypto_scalarmult_SCALARBYTES,
                           0);
    crypto_scalarmult_curve25519_base(ntor_public_key.data(),
                                      secret_ntor.data());
  }
  ~TorConnection() {
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&rsa_pk);
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
  void parse_cell(std::vector<uint8_t> &return_buffer,
                  std::vector<uint8_t> &send_buffer,
                  std::vector<uint8_t> &initiator_log) {
    uint64_t cursor = 0;
    auto circ_id = parse_uint16(return_buffer, cursor);
    if (!circ_id.has_value()) {
      return;
    }
    auto command = parse_uint8(return_buffer, cursor);
    if (!command.has_value()) {
      return;
    }

    if (command.value() == 7 || command.value() >= 128) { // variable length

      auto length = parse_uint16(return_buffer, cursor);
      if (!length.has_value()) {
        return;
      }

      uint16_t real_length = ntohs(length.value());

      auto payload = parse_fixed_buffer(return_buffer, cursor, real_length);
      if (!payload.has_value()) {
        return;
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
        return;
      }

      switch (command.value()) {
      case 8: {
        // we also dont gaf about the incoming netinfo
        // but we should get ready to send out own packets!

        if (!sent_auth) {

          printf("sending my auth!\n");
          generate_cert_cell(send_buffer);
          initiator_log.insert(initiator_log.end(), send_buffer.begin(),
                               send_buffer.end());

          generate_authenticate_cell(send_buffer, initiator_log);
          generate_netinfo_cell(send_buffer);

          // generate_create2_cell(send_buffer, 0x8001);
          generate_create2_cell(send_buffer, 0x0001);
          // generate_begin_relay_cell(send_buffer, 22, 22, "foxmoss.com:80",
          // 0);
        }

        break;
      }
      case 11: {
        printf("read CREATED2\n");
        break;
      }
      }
    }

    printf("%i\n", ntohs(circ_id.value()));
    printf("%i\n", command.value());
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
  }

  void generate_begin_relay_cell(std::vector<uint8_t> &send_buffer,
                                 uint16_t circuit_id, uint16_t stream_id,
                                 std::string addrport, uint32_t flags) {
    std::vector<uint8_t> data;
    data.insert(data.end(), addrport.begin(), addrport.end());
    data.push_back(0);

    flags = htonl(flags);
    data.insert(data.end(), (uint8_t *)&flags,
                (uint8_t *)&flags + sizeof(uint32_t));

    generate_relay_cell(send_buffer, 1, circuit_id, stream_id, data);
  }

private:
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
    // tf do we write to the end???
    int der_len =
        mbedtls_pk_write_pubkey_der(&crt.pk, der_buf, sizeof(der_buf));
    mbedtls_x509_crt_free(&crt);

    FILE *rsa_file = fopen("rsa.log", "w");
    printf("%s\n", der_buf + 4096 - der_len);

    fwrite(der_buf + 4096 - der_len, der_len, 1, rsa_file);
    remote_KP_relayid_rsa.insert(remote_KP_relayid_rsa.end(),
                                 der_buf + 4096 - der_len, der_buf + 4096);
    fclose(rsa_file);
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
        printf("TLS_LINK_X509 = 0x01\n");
        break;
      case RSA_ID_X509:
        parse_x509_cert(cert.value());

        printf("RSA_ID_X509 = 0x02\n");
        break;
      case LINK_AUTH_X509:
        printf("LINK_AUTH_X509 = 0x03\n");
        break;
      case IDENTITY_V_SIGNING:
        printf("IDENTITY_V_SIGNING = 0x04\n");
        break;
      case SIGNING_V_TLS_CERT:
        printf("SIGNING_V_TLS_CERT = 0x05\n");
        break;
      case SIGNING_V_LINK_AUTH:
        printf("SIGNING_V_LINK_AUTH = 0x06\n");
        break;
      case RSA_ID_V_IDENTITY:
        parse_rsa_cert(cert.value());
        printf("RSA_ID_V_IDENTITY = 0x07\n");
        break;
      case BLINDED_ID_V_SIGNING:
        printf("BLINDED_ID_V_SIGNING = 0x08\n");
        break;
      case HS_IP_V_SIGNING:
        printf("HS_IP_V_SIGNING = 0x09\n");
        break;
      case NTOR_CC_IDENTITY:
        printf("NTOR_CC_IDENTITY = 0x0A\n");
        break;
      case HS_IP_CC_SIGNING:
        printf("HS_IP_CC_SIGNING = 0x0B\n");
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

    printf("adding challenge\n");
    auth_challenges.push_back(challenge.value());

    return true;
  }
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

      auth_buffer.insert(auth_buffer.end(), keying_material.begin(),
                         keying_material.end());

      std::vector<uint8_t> random_buf;
      random_buf.insert(random_buf.end(), 24, 0);
      psa_generate_random(random_buf.data(), random_buf.size());

      auth_buffer.insert(auth_buffer.end(), random_buf.begin(),
                         random_buf.end());

      unsigned char signature[crypto_sign_BYTES];
      crypto_sign_detached(signature, NULL, auth_buffer.data(),
                           auth_buffer.size(), link_secret_key.data());

      auth_buffer.insert(auth_buffer.end(), signature,
                         signature + crypto_sign_BYTES);

      // put in buffer
      uint16_t auth_length = auth_buffer.size();
      auth_length = htons(auth_length);
      data.insert(data.end(), (uint8_t *)&auth_type,
                  (uint8_t *)&auth_type + sizeof(uint16_t));
      data.insert(data.end(), (uint8_t *)&auth_length,
                  (uint8_t *)&auth_length + sizeof(uint16_t));
      data.insert(data.end(), auth_buffer.begin(), auth_buffer.end());

      generate_cell_variable(send_buffer, 0, 131, data);
    }

    auth_challenges.clear();
  }

  void generate_cert_cell(std::vector<uint8_t> &send_buffer) {
    std::vector<uint8_t> data = {};
    data.push_back(1); // one cert!

    for (auto cert : local_certs) {
      // first cert
      data.push_back(cert.first); // one cert!

      uint16_t cert_len = cert.second.size();
      cert_len = htons(cert_len);

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

  void add_padding_b64(std::string &b64) {
    while (b64.size() % 4 != 0) {
      b64.push_back('=');
    }
  }

  std::vector<uint8_t> secret_ntor;
  std::vector<uint8_t> ntor_public_key;
  void generate_create2_cell(std::vector<uint8_t> &return_buffer,
                             uint16_t circuit_id) {
    std::vector<uint8_t> data = {};
    uint16_t htype = htons(0x0002);
    data.insert(data.end(), (uint8_t *)&htype,
                (uint8_t *)&htype + sizeof(uint16_t));

    std::vector<uint8_t> handshake_data = {};

    // identity
    std::vector<uint8_t> identity_digest;
    identity_digest.insert(identity_digest.end(), 20, 0);

    std::string identity_b64 = "UTn5b9ue3RAztREWSlkNXavQ/gI";
    add_padding_b64(identity_b64);
    size_t identity_len;
    mbedtls_base64_decode(
        (unsigned char *)identity_digest.data(), 20, &identity_len,
        (const unsigned char *)identity_b64.c_str(), identity_b64.size());

    FILE *identity_file = fopen("identity_digest.log", "w");
    fwrite(identity_digest.data(), identity_digest.size(), 1, identity_file);
    fclose(identity_file);

    handshake_data.insert(handshake_data.end(), identity_digest.begin(),
                          identity_digest.end());

    // ntor
    //
    std::vector<uint8_t> remote_ntor_pub_key;
    remote_ntor_pub_key.insert(remote_ntor_pub_key.end(), 32, 0);
    std::string remote_ntor_b64 = "VBPBxxdEhFqhXgkSTn918UvEewMamhoPjZvMQzEe+2o";
    add_padding_b64(remote_ntor_b64);
    size_t remote_ntor_len;
    mbedtls_base64_decode(
        (unsigned char *)remote_ntor_pub_key.data(), 32, &remote_ntor_len,
        (const unsigned char *)remote_ntor_b64.c_str(), remote_ntor_b64.size());

    handshake_data.insert(handshake_data.end(), remote_ntor_pub_key.begin(),
                          remote_ntor_pub_key.end());

    // new pub key
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);

    mbedtls_mpi temp_priv_key;
    mbedtls_mpi_init(&temp_priv_key);
    mbedtls_ecp_point temp_pub_key_raw;
    mbedtls_ecp_point_init(&temp_pub_key_raw);
    mbedtls_ecdh_gen_public(&grp, &temp_priv_key, &temp_pub_key_raw,
                            mbedtls_ctr_drbg_random, &ctr_drbg);

    std::vector<uint8_t> temp_pub_key;
    temp_pub_key.insert(temp_pub_key.end(), 32, 0);
    size_t olen = 0;
    mbedtls_ecp_point_write_binary(&grp, &temp_pub_key_raw,
                                   MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                   temp_pub_key.data(), 32);

    printf("pub key len %zu\n", olen);

    mbedtls_mpi_free(&temp_priv_key);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&temp_pub_key_raw);

    handshake_data.insert(handshake_data.end(), temp_pub_key.begin(),
                          temp_pub_key.end());

    uint16_t hlength = htons(handshake_data.size());
    data.insert(data.end(), (uint8_t *)&hlength,
                (uint8_t *)&hlength + sizeof(uint16_t));
    data.insert(data.end(), handshake_data.begin(), handshake_data.end());

    generate_cell_fixed(return_buffer, circuit_id, 10, data);
  }

  mbedtls_sha1_context sha1_ctx;
  // relay things
  void generate_relay_cell(std::vector<uint8_t> &send_buffer,
                           uint8_t relay_command, uint16_t circuit_id,
                           uint16_t stream_id,
                           std::vector<uint8_t> command_data) {
    std::vector<uint8_t> data = {};

    data.push_back(relay_command);
    data.insert(data.end(), 2,
                0); // two bytes for recognized, we shouldn't need to
                    // encrypt/decrypt this
    stream_id = htons(stream_id);
    data.insert(data.end(), (uint8_t *)&stream_id,
                (uint8_t *)&stream_id + sizeof(uint16_t));

    auto digest_reference = data.end() - 1;
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

    mbedtls_sha1_starts(&sha1_ctx);

    mbedtls_sha1_update(&sha1_ctx, data.data(), data.size());

    uint8_t digest_full[20];
    mbedtls_sha1_finish(&sha1_ctx, digest_full);

    data.erase(digest_reference + 1, digest_reference + 1 + 4);
    data.insert(digest_reference + 1, (uint8_t *)digest_full,
                (uint8_t *)digest_full + 4);

    mbedtls_sha1_free(&sha1_ctx);

    generate_cell_fixed(send_buffer, circuit_id, 3, data);
  }

  // crypto bs
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
};
