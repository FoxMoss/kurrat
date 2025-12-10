#pragma once
#include "mbedtls/pk.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
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
  TorConnection() {}
  ~TorConnection() {}

  void generate_versions_cell(std::vector<uint8_t> &return_buffer) {
    std::vector<uint8_t> data = {};
    uint16_t version_data = htons(3);
    data.insert(data.end(), (uint8_t *)&version_data,
                (uint8_t *)&version_data + sizeof(uint16_t));
    generate_cell_variable(return_buffer, 0, 7, data);
  }

  void parse_cell(std::vector<uint8_t> &return_buffer) {
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
      case 8: {
        // we also dont gaf about the incoming netinfo
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
    }

    printf("%i\n", ntohs(circ_id.value()));
    printf("%i\n", command.value());
    return_buffer.erase(return_buffer.begin(), return_buffer.begin() + cursor);
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

  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> certs;
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

      certs.push_back({cert_type.value(), cert.value()});

      switch ((CertType)cert_type.value()) {
      case TLS_LINK_X509:
        printf("TLS_LINK_X509 = 0x01\n");
        break;
      case RSA_ID_X509:
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
};
