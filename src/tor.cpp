#include "tor.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>

bool TorConnection::parse_relay(std::vector<uint8_t> &relay_buffer,
                                uint64_t &cursor) {

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

  if (!length.has_value() || !relay_command.has_value()) {
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
    break;
  case 3:
    return parse_end_relay(relay_payload.value(), relay_payload_cursor);
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
