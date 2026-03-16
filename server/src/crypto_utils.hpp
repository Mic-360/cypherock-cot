#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class CryptoUtils {
 public:
  [[nodiscard]] static std::array<uint8_t, 32> generateScalar();

  [[nodiscard]] static std::array<uint8_t, 33> scalarBaseMultiply(
      const std::array<uint8_t, 32>& scalar);

  [[nodiscard]] static std::array<uint8_t, 33> scalarPointMultiply(
      const std::array<uint8_t, 32>& scalar,
      const std::array<uint8_t, 33>& point);

  [[nodiscard]] static std::array<uint8_t, 33> pointAdd(
      const std::array<uint8_t, 33>& a, const std::array<uint8_t, 33>& b);

  [[nodiscard]] static std::array<uint8_t, 33> pointSubtract(
      const std::array<uint8_t, 33>& a, const std::array<uint8_t, 33>& b);

  [[nodiscard]] static std::array<uint8_t, 32> getXCoordinate(
      const std::array<uint8_t, 33>& point);

  [[nodiscard]] static std::vector<uint8_t> aesEncrypt(
      const std::array<uint8_t, 32>& key,
      const std::array<uint8_t, 32>& plaintext);

  [[nodiscard]] static std::array<uint8_t, 32> aesDecrypt(
      const std::array<uint8_t, 32>& key,
      const std::vector<uint8_t>& ciphertext_with_iv);

  [[nodiscard]] static std::array<uint8_t, 32> deriveAesKey(
      const std::array<uint8_t, 32>& xCoordinate);

  [[nodiscard]] static std::array<uint8_t, 32> scalarAdd(
      const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);

  [[nodiscard]] static std::array<uint8_t, 32> scalarNegate(
      const std::array<uint8_t, 32>& a);

  [[nodiscard]] static std::array<uint8_t, 32> scalarMul(
      const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);

  [[nodiscard]] static int getBit(const std::array<uint8_t, 32>& scalar,
                                  int i);

  [[nodiscard]] static std::array<uint8_t, 32> scalarShiftLeft(
      const std::array<uint8_t, 32>& scalar, int bits);

  [[nodiscard]] static std::string toHex(const std::array<uint8_t, 32>& data);

  [[nodiscard]] static std::string toHex33(const std::array<uint8_t, 33>& data);
};

#endif
