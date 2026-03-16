#include "ot_session.hpp"

#include "crypto_utils.hpp"

#include <iostream>
#include <cstring>
#include <stdexcept>

extern "C" {
#include "memzero.h"
}

OTSession::OTSession(const std::array<uint8_t, 32>& x) : x_(x) {
  rounds_.reserve(256);
}

std::array<uint8_t, 33> OTSession::prepareRound(int i) {
  if (i < 1 || i > 256) {
    throw std::runtime_error("Round index out of range: " + std::to_string(i));
  }

  OTRound round{};
  round.index = i;

  round.a = CryptoUtils::generateScalar();
  round.A = CryptoUtils::scalarBaseMultiply(round.a);

  round.Ui = CryptoUtils::generateScalar();

  round.m0 = round.Ui;

  round.m1 = CryptoUtils::scalarAdd(round.Ui, x_);

  rounds_.push_back(round);

  return round.A;
}

OTSession::EncryptedPair OTSession::processResponse(
    int i, const std::array<uint8_t, 33>& B) {
  if (i < 1 || i > static_cast<int>(rounds_.size())) {
    throw std::runtime_error("Invalid round index: " + std::to_string(i));
  }

  auto& round = rounds_[i - 1];
  if (round.index != i) {
    throw std::runtime_error("Round index mismatch");
  }

  auto aB = CryptoUtils::scalarPointMultiply(round.a, B);
  auto xCoord0 = CryptoUtils::getXCoordinate(aB);
  auto k0 = CryptoUtils::deriveAesKey(xCoord0);

  auto BminusA = CryptoUtils::pointSubtract(B, round.A);
  auto aBminusA = CryptoUtils::scalarPointMultiply(round.a, BminusA);
  auto xCoord1 = CryptoUtils::getXCoordinate(aBminusA);
  auto k1 = CryptoUtils::deriveAesKey(xCoord1);

  round.e0 = CryptoUtils::aesEncrypt(k0, round.m0);
  round.e1 = CryptoUtils::aesEncrypt(k1, round.m1);

  memzero(k0.data(), k0.size());
  memzero(k1.data(), k1.size());
  memzero(xCoord0.data(), xCoord0.size());
  memzero(xCoord1.data(), xCoord1.size());

  return {round.e0, round.e1};
}

std::array<uint8_t, 32> OTSession::computeAdditiveShare() const {

  for (const auto& round : rounds_) {
    auto term = CryptoUtils::scalarShiftLeft(round.Ui, round.index - 1);
    sum = CryptoUtils::scalarAdd(sum, term);
  }

  // flip the sum
  return CryptoUtils::scalarNegate(sum);
}
