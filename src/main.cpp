#include "mbedtls/pk.h"
#include "psa/crypto.h"
#include "tor.hpp"
#include <arpa/inet.h>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
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

  mbedtls_net_connect(&server_ctx, "107.189.1.175", "9001",
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

  TorConnection connection;

  // https://torspec-12e191.pages.torproject.net/tor-spec/opening-streams.html#opening
  std::string inital_addr = "107.189.1.175:9001";

  std::vector<uint8_t> return_buffer = {};
  connection.generate_versions_cell(return_buffer);

  FILE *from_me = fopen("from_me.log", "w");
  mbedtls_ssl_write(&ssl, return_buffer.data(), return_buffer.size());
  fwrite(return_buffer.data(), return_buffer.size(), 1, from_me);
  fflush(from_me);

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

    connection.parse_cell(read_buffer);

    fwrite(buf, size, 1, log_file);
    fflush(log_file);
  }
  fclose(log_file);

  mbedtls_ssl_free(&ssl);
  mbedtls_net_free(&server_ctx);
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
}
