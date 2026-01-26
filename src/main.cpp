#include "ansicolors.hpp"
#include "exitnodes.hpp"
#include "keys.hpp"
#include "mbedtls/pk.h"
#include "tor.hpp"
#include <CLI/CLI.hpp>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
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

int no_retry_mbedtls_net_connect(mbedtls_net_context *ctx, const char *host,
                                 const char *port, int proto) {
  int ret;
  struct addrinfo hints, *addr_list, *cur;

  /* Do name resolution with both IPv6 and IPv4 */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
  hints.ai_protocol =
      proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

  if (getaddrinfo(host, port, &hints, &addr_list) != 0) {
    return (MBEDTLS_ERR_NET_UNKNOWN_HOST);
  }

  /* Try the sockaddrs until a connection succeeds */
  ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
  for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
    ctx->fd = (int)socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
    if (ctx->fd < 0) {
      ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
      continue;
    }

    // https://stackoverflow.com/a/46473173
    struct timeval timeout;
    timeout.tv_sec = 1; // after 7 seconds connect() will timeout
    timeout.tv_usec = 0;
    setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0) {
      ret = 0;
      break;
    }

    setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, NULL, 0);

    close(ctx->fd);
    ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
  }

  freeaddrinfo(addr_list);

  return (ret);
}

/*
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⣀⡶⠚⠳⣴⠔⠆⠸⠷⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠶⢭⠉⠃⣴⠆⢀⣄⠈⠃⢤⢆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢨⢺⡾⢀⢱⡄⠰⡀⠨⠐⠡⢒⢛⢖⠂⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣌⢁⠀⢁⠠⠐⠈⡤⣀⣀⠠⠁⡽⠟⣀⡀⠀⠀⠀
⠀⠀⠀⠀⣴⡀⠉⠉⢩⣁⠺⠳⠳⠀⠠⡕⠋⠃⡀⣊⣠⢦⡃⠀⠀⠀
⠀⠀⠀⠊⢜⡋⣠⡄⣀⣡⡀⢠⡈⠘⠁⡘⣃⣤⡀⠉⠁⡉⠀⠀⠀⠀
⠀⠀⠀⠀⠑⣿⠎⠁⠁⠙⠇⠆⣁⡂⣀⣌⠛⡍⢁⠀⠀⡀⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠉⠰⣦⣤⠄⠀⠈⠈⢸⡆⠁⠁⢔⠊⠡⠐⠃⠀⠀⠀⠀ _                         _   
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

  app.set_version_flag("-v,--version", "v0.0.2");

  std::string key_path;
  app.add_option("key_folder", key_path, "The path of your key folder")
      ->required();

  std::optional<unsigned int> socks5_port = {};
  app.add_option("-p,--port", socks5_port,
                 "The port the SOCKS5 sever will start on")
      ->group("SOCKS5 OPTIONS");

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

  std::optional<std::string> requested_exit_addr = {};
  auto addr_opt = app.add_option("--exit_addr", requested_exit_addr,
                                 "Optional predefined exit node")
                      ->group("EXIT SELECTION");

  std::optional<std::string> requested_exit_port = {};
  auto port_opt = app.add_option("--exit_port", requested_exit_port,
                                 "Optional predefined exit node port")
                      ->group("EXIT SELECTION")
                      ->needs(addr_opt);

  std::optional<std::string> requested_exit_identity_b64 = {};
  auto identity_b64_opt =
      app.add_option(
             "--exit_identity_b64", requested_exit_identity_b64,
             "Optional predefined exit node identity key encoded in base64")
          ->group("EXIT SELECTION")
          ->needs(addr_opt);

  std::optional<std::string> requested_exit_ntor_b64 = {};
  auto ntor_b64_opt =
      app.add_option("--exit_ntor_b64", requested_exit_ntor_b64,
                     "Optional predefined exit node ntor key encoded in base64")
          ->group("EXIT SELECTION")
          ->needs(addr_opt);

  addr_opt->needs(port_opt)->needs(identity_b64_opt)->needs(ntor_b64_opt);

  CLI11_PARSE(app, argc, argv);

  printf(

      GRN
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⢰⣀⡶⠚⠳⣴⠔⠆⠸⠷⠀⠀⠀⠀⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⠀⢀⠶⢭⠉⠃⣴⠆⢀⣄⠈⠃⢤⢆⠀⠀⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⠀⢨⢺⡾⢀⢱⡄⠰⡀⠨⠐⠡⢒⢛⢖⠂⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠀⢀⣌⢁⠀⢁⠠⠐⠈⡤⣀⣀⠠⠁⡽⠟⣀⡀⠀⠀⠀\n"
      "⠀⠀⠀⠀⣴⡀⠉⠉⢩⣁⠺⠳⠳⠀⠠⡕⠋⠃⡀⣊⣠⢦⡃⠀⠀⠀\n"
      "⠀⠀⠀⠊⢜⡋⣠⡄⣀⣡⡀⢠⡈⠘⠁⡘⣃⣤⡀⠉⠁⡉⠀⠀⠀⠀\n"
      "⠀⠀⠀⠀⠑⣿⠎⠁⠁⠙⠇⠆⣁⡂⣀⣌⠛⡍⢁⠀⠀⡀⠂⠀⠀⠀\n"
      "⠀⠀⠀⠀⠀⠉⠰⣦⣤⠄⠀⠈⠈⢸⡆⠁⠁⢔⠊⠡⠐⠃⠀⠀⠀⠀ _                         _   \n" 
      "⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠠⠀⠀⠀⣷⠀⢶⠰⡆⠌⠁⠀⠀⠀⠀⠀| | ___   _ _ __ _ __ __ _| |_ \n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀| |/ / | | | '__| '__/ _` | __|\n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀ |   <| |_| | |  | | | (_| | |_ \n"
      "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀|_|\\_\\\\__,_|_|  |_|  \\__,_|\\__|\n\n\n");
  printf(GRN "[main] finding exit node\n");

  std::optional<MMDB_s> mmdb = {};
  if (maxmind_path.has_value()) {
    mmdb = MMDB_s();
    if (MMDB_open(maxmind_path->c_str(), 0, &mmdb.value()) != 0) {
      fprintf(stderr, RED "[exit] couldnt load maxminddb file");
      return {};
    }
  }

  auto exit_canidates = grab_consensus(mmdb, country);
  if (!exit_canidates.has_value()) {
    fprintf(stderr, RED "[exit] failed to grab exit canidates\n");
    return 1;
  }

  std::optional<ExitInfo> exit_node;

  if (!requested_exit_addr.has_value()) {

    exit_node = find_exit_node(mmdb, country, exit_canidates->second,
                               exit_canidates->first);

    if (maxmind_path.has_value()) {
      MMDB_close(&mmdb.value());
    }

    if (!exit_node.has_value()) {
      fprintf(stderr, RED "[exit] failed to select exit node\n");
      return 1;
    }
  } else {
    exit_node = ExitInfo{.idenity_key = requested_exit_identity_b64.value(),
                         .ip = requested_exit_addr.value(),
                         .port = requested_exit_port.value(),
                         .ntor_key = requested_exit_ntor_b64.value()};
  }

  std::thread socks_thread([socks5_port] {
    printf(GRN "[socks] starting socks5 server on 0.0.0.0:%s\n",
           std::to_string(socks5_port.value_or(1080)).c_str());

    setup_socks(socks5_port.value_or(1080), TorConnection::create_unix_socket);
  });
  socks_thread.detach();

  size_t connection_restarts = 0;

  while (true) {
    mbedtls_net_context tcp_net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_net_init(&tcp_net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    auto keys_parsed = parse_keys_from_folder(key_path, &ctr_drbg);
    if (!keys_parsed.has_value()) {
      fprintf(stderr, RED "[keys] error parsing keys: %s\n",
              keys_parsed.error().c_str());
      return -1;
    }

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)"client", 6);

    std::string exit_addr_str = exit_node->ip;
    std::string exit_identity_b64 = exit_node->idenity_key;
    std::string exit_ntor_b64 = exit_node->ntor_key;
    std::string exit_port = exit_node->port;

    printf(
        GRN
        "[exit] --exit_addr %s --exit_port %s\n       --exit_identity_b64 %s "
        "\n       --exit_ntor_b64 %s\n",
        exit_addr_str.c_str(), exit_port.c_str(), exit_identity_b64.c_str(),
        exit_ntor_b64.c_str());

    if (no_retry_mbedtls_net_connect(&tcp_net, exit_addr_str.c_str(),
                                     exit_port.c_str(),
                                     MBEDTLS_NET_PROTO_TCP) != 0) {
      exit_node = find_exit_node(mmdb, country, exit_canidates->second,
                                 exit_canidates->first, connection_restarts);

      goto end_loop;
    }
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_setup(&ssl, &conf);

    mbedtls_ssl_set_bio(&ssl, &tcp_net, mbedtls_net_send, mbedtls_net_recv,
                        NULL);

    if (mbedtls_ssl_handshake(&ssl) != 0) {
      goto end_loop;
    }

    {
      mbedtls_net_set_nonblock(&tcp_net);

      // reduce size format of ip addresses

      struct in_addr other_addr;
      inet_pton(AF_INET, exit_addr_str.c_str(), &other_addr);
      uint32_t other_addr_raw = other_addr.s_addr;

      auto connection_opt = make_tor_connection(
          keys_parsed->secret_id_key, keys_parsed->master_id_secret_key_raw,
          keys_parsed->signing_secret_key, keys_parsed->ntor_key, &ctr_drbg,
          exit_ntor_b64, exit_identity_b64, other_addr_raw, ssl);

      if (!connection_opt.has_value()) {
        fprintf(stderr, RED "[tor] error creating connection: %s\n",
                connection_opt.error().c_str());
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

        auto connection_send_buffer =
            connection.step(read_buffer, initiator_log);

        if (!connection_send_buffer->empty()) {
          mbedtls_ssl_write(&ssl, connection_send_buffer->data(),
                            connection_send_buffer->size());

          connection_send_buffer->clear();
        }

        unsigned char buf[BUFFER_SIZE];

        size = mbedtls_ssl_read(&ssl, buf, BUFFER_SIZE);
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
    }

  end_loop:
    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&tcp_net);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    mbedtls_pk_free(&keys_parsed->secret_id_key);

    if (killed_manually) {
      return 0;
    }
    fprintf(stderr, YEL "[main] restarting connection\n");
    connection_restarts++;
  }

  printf(COLOR_RESET);
}
