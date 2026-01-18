#include <thread>
extern "C" {
#include "donna/ed25519_donna_tor.h"
}
#include "exitnodes.hpp"
#include "keys.hpp"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "tor.hpp"
#include <CLI/CLI.hpp>
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

/*
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⣀⡶⠚⠳⣴⠔⠆⠸⠷⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠶⢭⠉⠃⣴⠆⢀⣄⠈⠃⢤⢆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢨⢺⡾⢀⢱⡄⠰⡀⠨⠐⠡⢒⢛⢖⠂⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣌⢁⠀⢁⠠⠐⠈⡤⣀⣀⠠⠁⡽⠟⣀⡀⠀⠀⠀
⠀⠀⠀⠀⣴⡀⠉⠉⢩⣁⠺⠳⠳⠀⠠⡕⠋⠃⡀⣊⣠⢦⡃⠀⠀⠀
⠀⠀⠀⠊⢜⡋⣠⡄⣀⣡⡀⢠⡈⠘⠁⡘⣃⣤⡀⠉⠁⡉⠀⠀⠀⠀
⠀⠀⠀⠀⠑⣿⠎⠁⠁⠙⠇⠆⣁⡂⣀⣌⠛⡍⢁⠀⠀⡀⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠉⠰⣦⣤⠄⠀⠈⠈⢸⡆⠁⠁⢔⠊⠡⠐⠃⠀⠀⠀⠀ _                        _   
⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠠⠀⠀⠀⣷⠀⢶⠰⡆⠌⠁⠀⠀⠀⠀⠀| | ___   _ _ __ _ __ __ _| |_ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀| |/ / | | | '__| '__/ _` | __|
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀ |   <| |_| | |  | | | (_| | |_ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀|_|\_\\__,_|_|  |_|  \__,_|\__|

*/

int main(int argc, char **argv) {
  find_exit_node();

  CLI::App app{"A single hop VPN that abuses The Tor Network", "kurrat"};

  app.set_version_flag("-v,--version", "v0.0.1");

  std::string key_path;
  app.add_option("key_folder", key_path, "The path of your key folder")
      ->required();

  CLI11_PARSE(app, argc, argv);

  printf(

      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⢰⣀⡶⠚⠳⣴⠔⠆⠸⠷⠀⠀⠀⠀⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⠀⢀⠶⢭⠉⠃⣴⠆⢀⣄⠈⠃⢤⢆⠀⠀⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⠀⢨⢺⡾⢀⢱⡄⠰⡀⠨⠐⠡⢒⢛⢖⠂⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⢀⣌⢁⠀⢁⠠⠐⠈⡤⣀⣀⠠⠁⡽⠟⣀⡀⠀⠀⠀\n"
      "⠀⠀⠀⠀⣴⡀⠉⠉⢩⣁⠺⠳⠳⠀⠠⡕⠋⠃⡀⣊⣠⢦⡃⠀⠀⠀\n"
      "⠀⠀⠀⠊⢜⡋⣠⡄⣀⣡⡀⢠⡈⠘⠁⡘⣃⣤⡀⠉⠁⡉⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠑⣿⠎⠁⠁⠙⠇⠆⣁⡂⣀⣌⠛⡍⢁⠀⠀⡀⠂⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠉⠰⣦⣤⠄⠀⠈⠈⢸⡆⠁⠁⢔⠊⠡⠐⠃⠀⠀⠀⠀ _                        _   \n"
      "⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠠⠀⠀⠀⣷⠀⢶⠰⡆⠌⠁⠀⠀⠀⠀⠀| | ___   _ _ __ _ __ __ _| |_ \n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀| |/ / | | | '__| '__/ _` | __|\n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀ |   <| |_| | |  | | | (_| | |_ \n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀|_|\\_\\\\__,_|_|  |_|  \\__,_|\\__|\n\n\n");

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

  auto keys_parsed = parse_keys_from_folder(key_path, &ctr_drbg);
  if (!keys_parsed.has_value()) {
    printf("error parsing keys: %s\n", keys_parsed.error().c_str());
    return -1;
  }
  auto connection_opt = make_tor_connection(
      keys_parsed->secret_id_key, keys_parsed->master_id_secret_key_raw,
      keys_parsed->signing_secret_key, keys_parsed->ntor_key, &ctr_drbg,
      remote_ntor_b64, remote_identity_b64, other_addr_raw, ssl);

  if (!connection_opt.has_value()) {
    printf("error creating connection: %s\n", connection_opt.error().c_str());
    return -1;
  }

  auto connection = connection_opt.value();
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
