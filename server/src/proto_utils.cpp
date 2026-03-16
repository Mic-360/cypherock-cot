/**
 * manual proto stuff
 *
 * using manual wire format bc nanopb is a headache
 * matches what protobufjs does on ts side logic
 */

#include "proto_utils.hpp"

#include <cstring>
#include <stdexcept>

static void encodeVarint(std::vector<uint8_t>& buf, uint64_t value) {
  while (value >= 0x80) {
    buf.push_back(static_cast<uint8_t>(value & 0x7F) | 0x80);
    value >>= 7;
  }
  buf.push_back(static_cast<uint8_t>(value));
}

static uint64_t decodeVarint(const uint8_t* data, size_t len, size_t& pos) {
  uint64_t result = 0;
  int shift = 0;
  while (pos < len) {
    uint8_t byte = data[pos++];
    result |= static_cast<uint64_t>(byte & 0x7F) << shift;
    if (!(byte & 0x80)) return result;
    shift += 7;
    if (shift > 63) throw std::runtime_error("Varint overflow");
  }
  throw std::runtime_error("end of varint unexpected");
}

static void encodeBytes(std::vector<uint8_t>& buf, uint32_t field_number,
                        const uint8_t* data, size_t len) {
  uint32_t key = (field_number << 3) | 2;
  encodeVarint(buf, key);
  encodeVarint(buf, len);
  buf.insert(buf.end(), data, data + len);
}

static void encodeBytes(std::vector<uint8_t>& buf, uint32_t field_number,
                        const std::vector<uint8_t>& data) {
  encodeBytes(buf, field_number, data.data(), data.size());
}

static void encodeUint32Field(std::vector<uint8_t>& buf,
                              uint32_t field_number, uint32_t value) {
  if (value == 0) return;
  uint32_t key = (field_number << 3) | 0;
  encodeVarint(buf, key);
  encodeVarint(buf, value);
}


static std::vector<uint8_t> encodeOTRoundInit(const ProtoMessage& msg) {
  std::vector<uint8_t> inner;
  encodeUint32Field(inner, 1, msg.round_index);
  if (!msg.point.empty()) {
    encodeBytes(inner, 2, msg.point);
  }
  return inner;
}

static std::vector<uint8_t> encodeOTRoundResponse(const ProtoMessage& msg) {
  std::vector<uint8_t> inner;
  encodeUint32Field(inner, 1, msg.round_index);
  if (!msg.point.empty()) {
    encodeBytes(inner, 2, msg.point);
  }
  return inner;
}

static std::vector<uint8_t> encodeOTEncryptedMsgs(const ProtoMessage& msg) {
  std::vector<uint8_t> inner;
  encodeUint32Field(inner, 1, msg.round_index);
  if (!msg.e0.empty()) {
    encodeBytes(inner, 2, msg.e0);
  }
  if (!msg.e1.empty()) {
    encodeBytes(inner, 3, msg.e1);
  }
  return inner;
}

static std::vector<uint8_t> encodeShareResult(const ProtoMessage& msg) {
  std::vector<uint8_t> inner;
  if (!msg.share.empty()) {
    encodeBytes(inner, 1, msg.share);
  }
  return inner;
}

static std::vector<uint8_t> encodeErrorMsg(const ProtoMessage& msg) {
  std::vector<uint8_t> inner;
  if (!msg.error_description.empty()) {
    encodeBytes(inner, 1,
                reinterpret_cast<const uint8_t*>(msg.error_description.data()),
                msg.error_description.size());
  }
  return inner;
}

std::vector<uint8_t> ProtoUtils::encode(const ProtoMessage& msg) {
  std::vector<uint8_t> buf;

  encodeUint32Field(buf, 1, static_cast<uint32_t>(msg.type));

  std::vector<uint8_t> inner;
  uint32_t payload_field = 0;

  switch (msg.type) {
    case MessageType::OT_ROUND_INIT:
      inner = encodeOTRoundInit(msg);
      payload_field = 2;
      break;
    case MessageType::OT_ROUND_RESPONSE:
      inner = encodeOTRoundResponse(msg);
      payload_field = 3;
      break;
    case MessageType::OT_ENCRYPTED_MSGS:
      inner = encodeOTEncryptedMsgs(msg);
      payload_field = 4;
      break;
    case MessageType::SHARE_RESULT:
      inner = encodeShareResult(msg);
      payload_field = 5;
      break;
    case MessageType::PROTOCOL_ERROR:
      inner = encodeErrorMsg(msg);
      payload_field = 6;
      break;
    default:
      break;
  }

  if (payload_field > 0 && !inner.empty()) {
    encodeBytes(buf, payload_field, inner);
  }

  return buf;
}

ProtoMessage ProtoUtils::decode(const std::vector<uint8_t>& data) {
  ProtoMessage msg;
  size_t pos = 0;
  const uint8_t* d = data.data();
  size_t len = data.size();

  while (pos < len) {
    uint64_t key = decodeVarint(d, len, pos);
    uint32_t field_number = static_cast<uint32_t>(key >> 3);
    uint32_t wire_type = static_cast<uint32_t>(key & 0x07);

    if (wire_type == 0) {
      uint64_t value = decodeVarint(d, len, pos);
      if (field_number == 1) {
        msg.type = static_cast<MessageType>(value);
      }
    } else if (wire_type == 2) {
      uint64_t field_len = decodeVarint(d, len, pos);
      if (pos + field_len > len) {
        throw std::runtime_error("field length exceeds boundary ig");
      }

      const uint8_t* field_data = d + pos;
      size_t flen = static_cast<size_t>(field_len);

      if (field_number == 2) {
        // OTRoundInit
        size_t ipos = 0;
        while (ipos < flen) {
          uint64_t ikey = decodeVarint(field_data, flen, ipos);
          uint32_t ifn = static_cast<uint32_t>(ikey >> 3);
          uint32_t iwt = static_cast<uint32_t>(ikey & 0x07);
          if (iwt == 0) {
            uint64_t val = decodeVarint(field_data, flen, ipos);
            if (ifn == 1) msg.round_index = static_cast<uint32_t>(val);
          } else if (iwt == 2) {
            uint64_t ilen = decodeVarint(field_data, flen, ipos);
            if (ifn == 2) {
              msg.point.assign(field_data + ipos,
                               field_data + ipos + ilen);
            }
            ipos += static_cast<size_t>(ilen);
          }
        }
      } else if (field_number == 3) {
        // OTRoundResponse
        size_t ipos = 0;
        while (ipos < flen) {
          uint64_t ikey = decodeVarint(field_data, flen, ipos);
          uint32_t ifn = static_cast<uint32_t>(ikey >> 3);
          uint32_t iwt = static_cast<uint32_t>(ikey & 0x07);
          if (iwt == 0) {
            uint64_t val = decodeVarint(field_data, flen, ipos);
            if (ifn == 1) msg.round_index = static_cast<uint32_t>(val);
          } else if (iwt == 2) {
            uint64_t ilen = decodeVarint(field_data, flen, ipos);
            if (ifn == 2) {
              msg.point.assign(field_data + ipos,
                               field_data + ipos + ilen);
            }
            ipos += static_cast<size_t>(ilen);
          }
        }
      } else if (field_number == 4) {
        // OTEncryptedMsgs
        size_t ipos = 0;
        while (ipos < flen) {
          uint64_t ikey = decodeVarint(field_data, flen, ipos);
          uint32_t ifn = static_cast<uint32_t>(ikey >> 3);
          uint32_t iwt = static_cast<uint32_t>(ikey & 0x07);
          if (iwt == 0) {
            uint64_t val = decodeVarint(field_data, flen, ipos);
            if (ifn == 1) msg.round_index = static_cast<uint32_t>(val);
          } else if (iwt == 2) {
            uint64_t ilen = decodeVarint(field_data, flen, ipos);
            if (ifn == 2) {
              msg.e0.assign(field_data + ipos, field_data + ipos + ilen);
            } else if (ifn == 3) {
              msg.e1.assign(field_data + ipos, field_data + ipos + ilen);
            }
            ipos += static_cast<size_t>(ilen);
          }
        }
      } else if (field_number == 5) {
        // ShareResult
        size_t ipos = 0;
        while (ipos < flen) {
          uint64_t ikey = decodeVarint(field_data, flen, ipos);
          uint32_t ifn = static_cast<uint32_t>(ikey >> 3);
          uint32_t iwt = static_cast<uint32_t>(ikey & 0x07);
          if (iwt == 2) {
            uint64_t ilen = decodeVarint(field_data, flen, ipos);
            if (ifn == 1) {
              msg.share.assign(field_data + ipos,
                               field_data + ipos + ilen);
            }
            ipos += static_cast<size_t>(ilen);
          } else if (iwt == 0) {
            decodeVarint(field_data, flen, ipos);  // skip
          }
        }
      } else if (field_number == 6) {
        // ErrorMsg
        size_t ipos = 0;
        while (ipos < flen) {
          uint64_t ikey = decodeVarint(field_data, flen, ipos);
          uint32_t ifn = static_cast<uint32_t>(ikey >> 3);
          uint32_t iwt = static_cast<uint32_t>(ikey & 0x07);
          if (iwt == 2) {
            uint64_t ilen = decodeVarint(field_data, flen, ipos);
            if (ifn == 1) {
              msg.error_description.assign(
                  reinterpret_cast<const char*>(field_data + ipos),
                  static_cast<size_t>(ilen));
            }
            ipos += static_cast<size_t>(ilen);
          } else if (iwt == 0) {
            decodeVarint(field_data, flen, ipos);  // skip
          }
        }
      }

      pos += flen;
    } else {
      throw std::runtime_error("Unsupported wire type: " +
                               std::to_string(wire_type));
    }
  }

  return msg;
}

std::vector<uint8_t> ProtoUtils::encodeFramed(const ProtoMessage& msg) {
  auto encoded = encode(msg);
  std::vector<uint8_t> framed(4 + encoded.size());
  writeLength(framed.data(), static_cast<uint32_t>(encoded.size()));
  std::memcpy(framed.data() + 4, encoded.data(), encoded.size());
  return framed;
}

uint32_t ProtoUtils::readLength(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

void ProtoUtils::writeLength(uint8_t* data, uint32_t length) {
  data[0] = static_cast<uint8_t>((length >> 24) & 0xFF);
  data[1] = static_cast<uint8_t>((length >> 16) & 0xFF);
  data[2] = static_cast<uint8_t>((length >> 8) & 0xFF);
  data[3] = static_cast<uint8_t>(length & 0xFF);
}
