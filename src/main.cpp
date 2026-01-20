#include "exitnodes.hpp"
#include "keys.hpp"
#include "mbedtls/pk.h"
#include "tor.hpp"
#include <CLI/CLI.hpp>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <linux/tls.h>
#include <maxminddb.h>
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
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

static volatile bool killed_manually = false;

void int_handler(int dummy) { killed_manually = true; }
void pipe_handler(int dummy) {}

int main(int argc, char **argv) {

  signal(SIGINT, int_handler);
  signal(SIGPIPE, pipe_handler);

  CLI::App app{"A single hop VPN that abuses The Tor Network", "kurrat"};

  app.set_version_flag("-v,--version", "v0.0.1");

  std::string key_path;
  app.add_option("key_folder", key_path, "The path of your key folder")
      ->required();

  std::optional<std::string> maxmind_path = {};
  auto maxmind_opt =
      app.add_option("-m,--maxminddb", maxmind_path,
                     "The path to a GeoLite2-City maxminddb file")
          ->group("EXIT SELECTION");

  std::optional<std::string> country = {};
  app.add_option("-c,--country", country,
                 "The country the tor exit node will be located in")
      ->group("EXIT SELECTION")
      ->needs(maxmind_opt);

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

  printf("finding exit node\n");

  std::optional<MMDB_s> mmdb = {};
  if (maxmind_path.has_value()) {
    mmdb = MMDB_s();
    if (MMDB_open(maxmind_path->c_str(), 0, &mmdb.value()) != 0) {
      printf("couldnt load maxminddb file");
      return {};
    }
  }

  auto exit_node = find_exit_node(mmdb, country);

  if (maxmind_path.has_value()) {
    MMDB_close(&mmdb.value());
  }

  if (!exit_node.has_value()) {
    printf("failed to select exit node\n");
    return 1;
  }

  std::thread socks_thread(
      [] { setup_socks(TorConnection::create_unix_socket); });
  socks_thread.detach();

  while (true) {

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

    // std::string other_addr_str = exit_node->ip;
    // std::string remote_identity_b64 = exit_node->idenity_key;
    // std::string remote_ntor_b64 = exit_node->ntor_key;
    // std::string or_port = exit_node->port;

    std::string other_addr_str = "127.0.0.1";
    std::string remote_identity_b64 = "JnAOtHlIDaMEWjtDS/es3uRvlP0";
    std::string remote_ntor_b64 = "q/qPlOcH+iQ6rQn6hY3gr+ekPlz3YY9seXagM9KZIks";
    std::string or_port = "9001";

    mbedtls_net_connect(&server_ctx, other_addr_str.c_str(), or_port.c_str(),
                        MBEDTLS_NET_PROTO_TCP);
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

    mbedtls_ssl_write(&ssl, send_buffer.data(), send_buffer.size());
    initiator_log.insert(initiator_log.end(), send_buffer.begin(),
                         send_buffer.end());
    send_buffer.clear();

    std::vector<uint8_t> read_buffer;
    int size;

    while (true) {
      if (connection.is_destroyed() || killed_manually) {
        goto end_loop;
      }

      std::vector<uint8_t> *return_send_buffer =
          connection.step(read_buffer, initiator_log);

      if (!return_send_buffer->empty()) {

        mbedtls_ssl_write(&ssl, return_send_buffer->data(),
                          return_send_buffer->size());

        return_send_buffer->clear();
      }

      unsigned char buf[1024];

      size = mbedtls_ssl_read(&ssl, buf, 1024);
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
    }

  end_loop:
    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&server_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    mbedtls_pk_free(&keys_parsed->secret_id_key);

    if (killed_manually) {
      return 0;
    }
    printf("restarting connection\n");
  }
}
