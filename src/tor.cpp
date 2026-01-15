#include "tor.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <unistd.h>

bool TorConnection::parse_relay(std::vector<uint8_t> &relay_buffer,
                                uint16_t circuit_id, uint64_t &cursor,
                                std::vector<uint8_t> &send_buffer) {

  std::vector<uint8_t> decrypted_buffer;
  decrypted_buffer.insert(decrypted_buffer.end(), relay_buffer.size(), 0);

  mbedtls_aes_crypt_ctr(
      &backward_aes_ctx, relay_buffer.size(), &backward_stream_offset,
      backward_stream_iv, backward_stream_block,
      (const uint8_t *)relay_buffer.data(), decrypted_buffer.data());

  auto relay_command = parse_uint8(decrypted_buffer, cursor);

  auto recoginized = parse_uint16(decrypted_buffer, cursor);
  auto stream_id = parse_uint16(decrypted_buffer, cursor);
  auto digest = parse_fixed_buffer(decrypted_buffer, cursor, 4);
  auto length = parse_uint16(decrypted_buffer, cursor);

  if (!length.has_value() || !relay_command.has_value() ||
      !stream_id.has_value()) {
    return false;
  }

  size_t relay_payload_cursor = 0;
  auto relay_payload =
      parse_fixed_buffer(decrypted_buffer, cursor, ntohs(length.value()));

  if (!relay_payload.has_value()) {
    return false;
  }

  printf("relay command %i\n", relay_command.value());

  switch (relay_command.value()) {
  case 4: // connected. no parsing needed!
    stream_map[stream_id.value()].connected = true;
    printf("connected to address through proxy!\n");
    break;

  case 5: // sendme, literally no data to parse
    my_global_sent_window += 100;
    break;

  case 3:
    return parse_end_relay(relay_payload.value(), relay_payload_cursor);
    break;
  case 2:
    return parse_data_relay(relay_payload.value(), circuit_id,
                            stream_id.value(), send_buffer);
    break;
  }
  return true;
}

bool TorConnection::parse_end_relay(std::vector<uint8_t> &end_buffer,
                                    uint64_t &cursor) {
  auto end_reason = parse_uint8(end_buffer, cursor);
  printf("end reason %i\n", end_reason.value());

  return true;
}

bool TorConnection::generate_send_me_relay(uint16_t circuit_id,
                                           uint16_t stream_id,
                                           std::vector<uint8_t> &send_buffer) {
  if (!stream_map.contains(stream_id))
    return false;

  std::vector<uint8_t> data = {};

  generate_relay_cell(send_buffer, 5, circuit_id, 0, data);
  return true;
}

bool TorConnection::parse_data_relay(std::vector<uint8_t> &data_buffer,
                                     uint16_t circuit_id, uint16_t stream_id,
                                     std::vector<uint8_t> &send_buffer) {

  if (!stream_map.contains(stream_id))
    return false;

  if (stream_map.contains(stream_id) &&
      stream_map[stream_id].file_descriptor_pipe.has_value()) {
    write(stream_map[stream_id].file_descriptor_pipe.value(),
          data_buffer.data(), data_buffer.size());
    printf("to fd %zu\n", data_buffer.size());
  }

  my_global_recived_window++;

  if (my_global_recived_window >= 100 &&
      generate_send_me_relay(circuit_id, stream_id, send_buffer)) {
    my_global_recived_window -= 100;
  }

  return true;
}

bool TorConnection::generate_data_relay(std::vector<uint8_t> &send_buffer,
                                        std::vector<uint8_t> data,
                                        uint16_t circuit_id,
                                        uint16_t stream_id) {

  if (!stream_map.contains(stream_id))
    return false;

  if (my_global_sent_window < 0)
    return false;

  generate_relay_cell(send_buffer, 2, circuit_id, stream_id, data);

  my_global_sent_window--;
  return true;
}
