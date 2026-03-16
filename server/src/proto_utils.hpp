#ifndef PROTO_UTILS_HPP
#define PROTO_UTILS_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

enum class MessageType : int {
  UNKNOWN = 0,
  OT_ROUND_INIT = 1,
  OT_ROUND_RESPONSE = 2,
  OT_ENCRYPTED_MSGS = 3,
  SHARE_RESULT = 4,
  PROTOCOL_ERROR = 5
};

struct ProtoMessage {
  MessageType type = MessageType::UNKNOWN;
  uint32_t round_index = 0;

  std::vector<uint8_t> point;

  std::vector<uint8_t> e0;
  std::vector<uint8_t> e1;
  std::vector<uint8_t> share;

  std::string error_description;
};

class ProtoUtils {
 public:
  [[nodiscard]] static std::vector<uint8_t> encode(const ProtoMessage& msg);

  [[nodiscard]] static ProtoMessage decode(const std::vector<uint8_t>& data);

  [[nodiscard]] static std::vector<uint8_t> encodeFramed(
      const ProtoMessage& msg);

  [[nodiscard]] static uint32_t readLength(const uint8_t* data);

  static void writeLength(uint8_t* data, uint32_t length);
};

#endif
