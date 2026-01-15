#include "tor.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static TorConnection *tor_connection = NULL;
void set_global_conn(TorConnection *c_tor_connection) {
  tor_connection = c_tor_connection;
}

int TorConnection::create_unix_socket(char *addr, uint16_t port,
                                      uint16_t stream_id) {
  std::lock_guard<std::mutex> guard(tor_connection->during_step);

  if (tor_connection == NULL) {
    printf("tor connection is null");
    return 0;
  }

  int pipefds[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, pipefds);
  fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
  int my_fd = pipefds[0];
  int return_fd = pipefds[1];

  struct addrinfo *raddr = NULL;
  getaddrinfo(addr, NULL, NULL, &raddr);

  char addr_str[INET6_ADDRSTRLEN];
  void *addr_ptr;
  if (raddr->ai_family == AF_INET) {
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)raddr->ai_addr;
    addr_ptr = &(ipv4->sin_addr);
  } else { // AF_INET6
    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)raddr->ai_addr;
    addr_ptr = &(ipv6->sin6_addr);
  }
  inet_ntop(raddr->ai_family, addr_ptr, addr_str, INET6_ADDRSTRLEN);

  freeaddrinfo(raddr);

  char addrport[256];
  snprintf(addrport, 256, "%s:%i", addr_str, port);
  printf("%s -> %s\n", addr, addrport);
  tor_connection->generate_begin_relay_cell(
      tor_connection->additional_send_buffer, tor_connection->global_circuit_id,
      stream_id, std::string(addrport), 0);

  printf("sending relay cell\n");

  tor_connection->stream_map[stream_id].file_descriptor_pipe = my_fd;

  return return_fd;
}
