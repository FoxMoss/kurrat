#include "tor.hpp"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

  std::vector<uint8_t> undigest_buffer = decrypted_buffer;
  memset(undigest_buffer.data() + 5, 0, 4);

  mbedtls_sha1_update(&backward_sha1_ctx, undigest_buffer.data(),
                      undigest_buffer.size());

  auto relay_command = parse_uint8(decrypted_buffer, cursor);

  auto recoginized = parse_uint16(decrypted_buffer, cursor);
  auto stream_id = parse_uint16(decrypted_buffer, cursor);
  auto digest = parse_fixed_buffer(decrypted_buffer, cursor, 4);
  auto length = parse_uint16(decrypted_buffer, cursor);

  if (!recoginized.has_value() || ntohs(recoginized.value()) != 0) {
    return false;
  }

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

  if (!stream_id.has_value() ||
      (!stream_map.contains(ntohs(stream_id.value())) &&
       ntohs(stream_id.value()) != 0)) {
    return false;
  }

  switch (relay_command.value()) {
  case 4: // connected. no parsing needed!
    stream_map[ntohs(stream_id.value())].connected = true;
    printf("a stream has connected!\n");
    break;

  case 5: // sendme, literally no data to parse
    if (ntohs(stream_id.value()) == 0) {
      my_global_sent_window += 100;
      break;
    }
    stream_map[ntohs(stream_id.value())].stream_sent_window += 50;
    break;

  case 3:
    if (stream_map[ntohs(stream_id.value())].file_descriptor_pipe.has_value())
      close(stream_map[ntohs(stream_id.value())].file_descriptor_pipe.value());

    stream_map.erase(ntohs(stream_id.value()));
    return parse_end_relay(relay_payload.value(), relay_payload_cursor);
    break;
  case 2:
    return parse_data_relay(relay_payload.value(), circuit_id,
                            ntohs(stream_id.value()), send_buffer);
    break;
  }
  return true;
}

bool TorConnection::parse_end_relay(std::vector<uint8_t> &end_buffer,
                                    uint64_t &cursor) {
  auto end_reason = parse_uint8(end_buffer, cursor);
  printf("stream has closed with end reason %i\n", end_reason.value());

  return true;
}

bool TorConnection::generate_send_me_relay(uint16_t circuit_id,
                                           uint16_t stream_id,
                                           std::vector<uint8_t> &send_buffer) {
  if (stream_id != 0 && !stream_map.contains(stream_id))
    return false;

  std::vector<uint8_t> data = {};

  if (stream_id == 0) {
    data.push_back(1);

    uint8_t digest_full[20] = {};
    mbedtls_sha1_context old_ctx;

    mbedtls_sha1_init(&old_ctx);
    mbedtls_sha1_clone(&old_ctx, &backward_sha1_ctx);

    mbedtls_sha1_finish(&old_ctx, digest_full);
    mbedtls_sha1_free(&old_ctx);

    uint16_t digest_len = htons(20);

    data.insert(data.end(), (uint8_t *)&digest_len,
                (uint8_t *)&digest_len + sizeof(uint16_t));
    data.insert(data.end(), digest_full, digest_full + 20);
  }

  generate_relay_cell(send_buffer, 5, circuit_id, stream_id, data);
  return true;
}

bool TorConnection::parse_data_relay(std::vector<uint8_t> &data_buffer,
                                     uint16_t circuit_id, uint16_t stream_id,
                                     std::vector<uint8_t> &send_buffer) {

  if (!stream_map.contains(stream_id))
    return false;

  if (stream_map.contains(stream_id) &&
      stream_map[stream_id].file_descriptor_pipe.has_value()) {
    int error = write(stream_map[stream_id].file_descriptor_pipe.value(),
                      data_buffer.data(), data_buffer.size());
    if (error == -EPIPE) {
      printf("silenty closed socket\n");
      if (stream_map[stream_id].file_descriptor_pipe.has_value())
        close(stream_map[stream_id].file_descriptor_pipe.value());

      stream_map.erase(stream_id);
      return false;
    }
  }

  my_global_recived_window++;
  stream_map[stream_id].stream_recived_window++;

  if (my_global_recived_window >= 100 &&
      generate_send_me_relay(circuit_id, 0, send_buffer)) {
    my_global_recived_window -= 100;
  }

  if (stream_map[stream_id].stream_recived_window >= 50 &&
      generate_send_me_relay(circuit_id, stream_id, send_buffer)) {
    stream_map[stream_id].stream_recived_window -= 50;
  }

  return true;
}

bool TorConnection::generate_data_relay(std::vector<uint8_t> &send_buffer,
                                        std::vector<uint8_t> data,
                                        uint16_t circuit_id,
                                        uint16_t stream_id) {

  if (!stream_map.contains(stream_id))
    return false;

  if (my_global_sent_window <= 0)
    return false;

  if (stream_map[stream_id].stream_sent_window <= 0)
    return false;

  generate_relay_cell(send_buffer, 2, circuit_id, stream_id, data);

  my_global_sent_window--;
  stream_map[stream_id].stream_sent_window--;
  return true;
}
