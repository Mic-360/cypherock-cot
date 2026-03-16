#ifndef OT_SESSION_HPP
#define OT_SESSION_HPP

#include <array>
#include <cstdint>
#include <vector>

struct OTRound {
  int index;
  std::array<uint8_t, 32> a;
  std::array<uint8_t, 33> A;
  std::array<uint8_t, 32> Ui;
  std::array<uint8_t, 32> m0;
  std::array<uint8_t, 32> m1;
  std::vector<uint8_t> e0;
  std::vector<uint8_t> e1;
};

class OTSession {
 public:
  explicit OTSession(const std::array<uint8_t, 32>& x);

  [[nodiscard]] std::array<uint8_t, 33> prepareRound(int i);

  struct EncryptedPair {
    std::vector<uint8_t> e0;
    std::vector<uint8_t> e1;
  };
  [[nodiscard]] EncryptedPair processResponse(
      int i, const std::array<uint8_t, 33>& B);

  [[nodiscard]] std::array<uint8_t, 32> computeAdditiveShare() const;

 private:
  std::array<uint8_t, 32> x_;
  std::vector<OTRound> rounds_;
};

#endif
