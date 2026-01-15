#include "tor.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>

static TorConnection *tor_connection = NULL;
void set_global_conn(TorConnection *c_tor_connection) {
  tor_connection = c_tor_connection;
}

int TorConnection::create_unix_socket(char *addrport, uint16_t stream_id) {
  std::lock_guard<std::mutex> guard(tor_connection->during_step);

  if (tor_connection == NULL) {
    printf("tor connection is null");
    return 0;
  }

  int pipefds[2];
  pipe2(pipefds, O_NONBLOCK);
  int my_fd = pipefds[0];
  int return_fd = pipefds[1];

  printf("%s %i\n", addrport, stream_id);
  tor_connection->generate_begin_relay_cell(
      tor_connection->additional_send_buffer, tor_connection->global_circuit_id,
      stream_id, std::string(addrport), 0);

  printf("sending relay cell\n");

  tor_connection->stream_map[stream_id].file_descriptor_pipe = my_fd;

  return return_fd;
}
