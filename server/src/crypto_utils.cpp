// crypto utils via trezor-crypto ig
// wraps bignum256, curve_point, aes, n sha256 for the ot protocol ig

#include "crypto_utils.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

extern "C" {
#include "bignum.h"
#include "ecdsa.h"
#include "memzero.h"
#include "rand.h"
#include "secp256k1.h"
#include "sha2.h"
#include "aes/aes.h"
}

static const uint8_t SECP256K1_ORDER[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static void bn_from_bytes(bignum256* bn, const uint8_t* data) {
  bn_read_be(data, bn);
}

static void bn_to_bytes(const bignum256* bn, uint8_t* out) {
  bn_write_be(bn, out);
}

static bool decompress_point(const uint8_t* compressed, curve_point* point) {
  return ecdsa_read_pubkey(&secp256k1, compressed, point) != 0;
}

static void compress_point_to(const curve_point* point, uint8_t* out) {
  compress_coords(point, out);
}

static void get_order(bignum256* order) {
  bn_read_be(SECP256K1_ORDER, order);
}

static void pkcs7_pad(const uint8_t* in, size_t in_len, uint8_t* out,
                      size_t block_size) {
  size_t pad_len = block_size - (in_len % block_size);
  std::memcpy(out, in, in_len);
  std::memset(out + in_len, static_cast<uint8_t>(pad_len), pad_len);
}

static size_t pkcs7_unpad(const uint8_t* in, size_t in_len) {
  if (in_len == 0) return 0;
  uint8_t pad_val = in[in_len - 1];
  if (pad_val == 0 || pad_val > 16) return in_len;
  return in_len - pad_val;
}

// public bits

std::array<uint8_t, 32> CryptoUtils::generateScalar() {
  bignum256 order;
  get_order(&order);

  std::array<uint8_t, 32> scalar{};
  bignum256 s;

  while (true) {
    random_buffer(scalar.data(), 32);
    bn_from_bytes(&s, scalar.data());

    if (bn_is_zero(&s)) continue;
    if (!bn_is_less(&s, &order)) continue;

    bn_to_bytes(&s, scalar.data());
    memzero(&s, sizeof(s));
    break;
  }

  return scalar;
}

std::array<uint8_t, 33> CryptoUtils::scalarBaseMultiply(
    const std::array<uint8_t, 32>& scalar) {
  bignum256 k;
  bn_from_bytes(&k, scalar.data());

  curve_point result;
  scalar_multiply(&secp256k1, &k, &result);

  std::array<uint8_t, 33> compressed{};
  compress_point_to(&result, compressed.data());

  memzero(&k, sizeof(k));
  memzero(&result, sizeof(result));
  return compressed;
}

std::array<uint8_t, 33> CryptoUtils::scalarPointMultiply(
    const std::array<uint8_t, 32>& scalar,
    const std::array<uint8_t, 33>& point) {
  bignum256 k;
  bn_from_bytes(&k, scalar.data());

  curve_point p;
  if (!decompress_point(point.data(), &p)) {
    throw std::runtime_error("Failed to decompress EC point");
  }

  curve_point result;
  point_multiply(&secp256k1, &k, &p, &result);

  std::array<uint8_t, 33> compressed{};
  compress_point_to(&result, compressed.data());

  memzero(&k, sizeof(k));
  memzero(&p, sizeof(p));
  memzero(&result, sizeof(result));
  return compressed;
}

std::array<uint8_t, 33> CryptoUtils::pointAdd(
    const std::array<uint8_t, 33>& a, const std::array<uint8_t, 33>& b) {
  curve_point pa, pb;
  if (!decompress_point(a.data(), &pa)) {
    throw std::runtime_error("Failed to decompress point A");
  }
  if (!decompress_point(b.data(), &pb)) {
    throw std::runtime_error("Failed to decompress point B");
  }

  point_add(&secp256k1, &pb, &pa);

  std::array<uint8_t, 33> compressed{};
  compress_point_to(&pa, compressed.data());

  memzero(&pa, sizeof(pa));
  memzero(&pb, sizeof(pb));
  return compressed;
}

std::array<uint8_t, 33> CryptoUtils::pointSubtract(
    const std::array<uint8_t, 33>& a, const std::array<uint8_t, 33>& b) {
  curve_point pa, pb;
  if (!decompress_point(a.data(), &pa)) {
    throw std::runtime_error("Failed to decompress point A");
  }
  if (!decompress_point(b.data(), &pb)) {
    throw std::runtime_error("Failed to decompress point B");
  }

  bn_subtract(&secp256k1.prime, &pb.y, &pb.y);
  bn_mod(&pb.y, &secp256k1.prime);

  point_add(&secp256k1, &pb, &pa);

  std::array<uint8_t, 33> compressed{};
  compress_point_to(&pa, compressed.data());

  memzero(&pa, sizeof(pa));
  memzero(&pb, sizeof(pb));
  return compressed;
}

std::array<uint8_t, 32> CryptoUtils::getXCoordinate(
    const std::array<uint8_t, 33>& point) {
  std::array<uint8_t, 32> x{};
  std::memcpy(x.data(), point.data() + 1, 32);
  return x;
}

std::array<uint8_t, 32> CryptoUtils::deriveAesKey(
    const std::array<uint8_t, 32>& xCoordinate) {
  std::array<uint8_t, 32> key{};
  sha256_Raw(xCoordinate.data(), 32, key.data());
  return key;
}

std::vector<uint8_t> CryptoUtils::aesEncrypt(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 32>& plaintext) {
  uint8_t iv[16];
  random_buffer(iv, 16);

  uint8_t padded[48];
  pkcs7_pad(plaintext.data(), 32, padded, 16);
  uint8_t encrypted[48];
  uint8_t iv_copy[16];
  std::memcpy(iv_copy, iv, 16);

  aes_encrypt_ctx ctx;
  aes_encrypt_key256(key.data(), &ctx);
  aes_cbc_encrypt(padded, encrypted, 48, iv_copy, &ctx);

  std::vector<uint8_t> result(16 + 48);
  std::memcpy(result.data(), iv, 16);
  std::memcpy(result.data() + 16, encrypted, 48);

  memzero(&ctx, sizeof(ctx));
  memzero(padded, sizeof(padded));
  memzero(iv, sizeof(iv));
  memzero(iv_copy, sizeof(iv_copy));
  return result;
}

std::array<uint8_t, 32> CryptoUtils::aesDecrypt(
    const std::array<uint8_t, 32>& key,
    const std::vector<uint8_t>& ciphertext_with_iv) {
  if (ciphertext_with_iv.size() < 32) {
    throw std::runtime_error("Ciphertext too short");
  }

  uint8_t iv[16];
  std::memcpy(iv, ciphertext_with_iv.data(), 16);

  const uint8_t* ciphertext = ciphertext_with_iv.data() + 16;
  int ct_len = static_cast<int>(ciphertext_with_iv.size()) - 16;

  std::vector<uint8_t> decrypted(static_cast<size_t>(ct_len));

  aes_decrypt_ctx ctx;
  aes_decrypt_key256(key.data(), &ctx);
  aes_cbc_decrypt(ciphertext, decrypted.data(), ct_len, iv, &ctx);

  size_t unpadded_len = pkcs7_unpad(decrypted.data(), static_cast<size_t>(ct_len));

  std::array<uint8_t, 32> result{};
  if (unpadded_len != 32) {
    throw std::runtime_error("Decrypted plaintext is not 32 bytes");
  }
  std::memcpy(result.data(), decrypted.data(), 32);

  memzero(&ctx, sizeof(ctx));
  return result;
}

std::array<uint8_t, 32> CryptoUtils::scalarAdd(
    const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
  bignum256 ba, bb, order;
  bn_from_bytes(&ba, a.data());
  bn_from_bytes(&bb, b.data());
  get_order(&order);

  bn_addmod(&ba, &bb, &order);

  std::array<uint8_t, 32> result{};
  bn_to_bytes(&ba, result.data());

  memzero(&ba, sizeof(ba));
  memzero(&bb, sizeof(bb));
  return result;
}

std::array<uint8_t, 32> CryptoUtils::scalarNegate(
    const std::array<uint8_t, 32>& a) {
  bignum256 ba, order;
  bn_from_bytes(&ba, a.data());
  get_order(&order);

  if (!bn_is_zero(&ba)) {
    bn_subtract(&order, &ba, &ba);
  }

  std::array<uint8_t, 32> result{};
  bn_to_bytes(&ba, result.data());

  memzero(&ba, sizeof(ba));
  return result;
}

std::array<uint8_t, 32> CryptoUtils::scalarMul(
    const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
  bignum256 ba, bb, order;
  bn_from_bytes(&ba, a.data());
  bn_from_bytes(&bb, b.data());
  get_order(&order);

  bn_multiply(&bb, &ba, &order);

  std::array<uint8_t, 32> result{};
  bn_to_bytes(&ba, result.data());

  memzero(&ba, sizeof(ba));
  memzero(&bb, sizeof(bb));
  return result;
}

int CryptoUtils::getBit(const std::array<uint8_t, 32>& scalar, int i) {
  if (i < 1 || i > 256) {
    throw std::runtime_error("Bit index out of range");
  }
  int byteIndex = 31 - (i - 1) / 8;
  int bitIndex = (i - 1) % 8;
  return (scalar[byteIndex] >> bitIndex) & 1;
}

std::array<uint8_t, 32> CryptoUtils::scalarShiftLeft(
    const std::array<uint8_t, 32>& scalar, int bits) {
  bignum256 s, pow2, order;
  bn_from_bytes(&s, scalar.data());
  get_order(&order);

  // math 2^bits mod n via repeated doubling ig bc 2^256 is too big
  bn_zero(&pow2);
  pow2.val[0] = 1;
  for (int i = 0; i < bits; i++) {
    bn_lshift(&pow2);
    bn_mod(&pow2, &order);
  }

  bn_multiply(&pow2, &s, &order);

  std::array<uint8_t, 32> result{};
  bn_to_bytes(&s, result.data());

  memzero(&s, sizeof(s));
  memzero(&pow2, sizeof(pow2));
  return result;
}

std::string CryptoUtils::toHex(const std::array<uint8_t, 32>& data) {
  std::stringstream ss;
  for (auto byte : data) {
    ss << std::hex << std::setfill('0') << std::setw(2)
       << static_cast<int>(byte);
  }
  return ss.str();
}

std::string CryptoUtils::toHex33(const std::array<uint8_t, 33>& data) {
  std::stringstream ss;
  for (auto byte : data) {
    ss << std::hex << std::setfill('0') << std::setw(2)
       << static_cast<int>(byte);
  }
  return ss.str();
}
