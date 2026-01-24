#pragma once

#include "mbedtls/pk.h"
#include "tor.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <filesystem>
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
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <tl/expected.hpp>
#include <unistd.h>
#include <vector>

#define UNWRAP(exp)                                                            \
  if (!exp.has_value())                                                        \
    return tl::unexpected(exp.error());

struct LinkKeys {
  std::vector<uint8_t> link_public_key, link_secret_key, cert;
};

tl::expected<mbedtls_pk_context, std::string>
read_rsa_secret_key(const char *file, void *ctr_drbg);
tl::expected<std::vector<uint8_t>, std::string> read_ed25519_secret_key();

tl::expected<std::vector<uint8_t>, std::string>
create_cross_cert(std::vector<uint8_t> master_id_secret_key_raw,
                  mbedtls_pk_context id_pk, void *ctr_drbg);

tl::expected<std::vector<uint8_t>, std::string>
create_rsa_id_cert(mbedtls_pk_context id_pk, void *ctr_drbg);

tl::expected<std::vector<uint8_t>, std::string>
create_id_cert(std::vector<uint8_t> master_id_secret_key_raw,
               std::vector<uint8_t> signing_secret_key);

tl::expected<std::vector<uint8_t>, std::string>
create_tls_cert(std::vector<uint8_t> signing_secret_key,
                std::vector<uint8_t> subject);

tl::expected<std::vector<uint8_t>, std::string>
read_ed25519_signing_key(const char *ed25519_signing_secret_key);

tl::expected<LinkKeys, std::string>
create_link_cert(const std::vector<uint8_t> &signing_secret_key);

tl::expected<TorConnection, std::string>
make_tor_connection(mbedtls_pk_context secret_id_key,
                    std::vector<uint8_t> master_id_secret_key_raw,
                    std::vector<uint8_t> signing_secret_key,
                    std::vector<uint8_t> ntor_key, void *ctr_drbg,
                    std::string remote_ntor_b64,
                    std::string remote_identity_b64, uint32_t other_addr_raw,
                    mbedtls_ssl_context ssl_context);

struct KeysParsed {
  mbedtls_pk_context secret_id_key;
  std::vector<uint8_t> master_id_secret_key_raw;
  std::vector<uint8_t> signing_secret_key;
  std::vector<uint8_t> ntor_key;
};

tl::expected<KeysParsed, std::string>
parse_keys_from_folder(std::filesystem::path folder_path, void *ctr_drbg);
