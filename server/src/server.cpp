#include "server.hpp"

#include <cstring>
#include <iostream>

#include "crypto_utils.hpp"

Session::Session(tcp::socket socket, const std::array<uint8_t, 32>& x)
    : socket_(std::move(socket)), otSession_(x), x_(x) {}

void Session::start() {
  try {
    runProtocol();
  } catch (const std::exception& e) {
    std::cerr << "[Server] Protocol error: " << e.what() << std::endl;
  }
}

void Session::runProtocol() {
  std::cout << "[Server] Client connected" << std::endl;

  for (int i = 1; i <= 256; i++) {
    auto A = otSession_.prepareRound(i);

    ProtoMessage initMsg;
    initMsg.type = MessageType::OT_ROUND_INIT;
    initMsg.round_index = static_cast<uint32_t>(i);
    initMsg.point.assign(A.begin(), A.end());
    sendMessage(initMsg);

    auto responseMsg = receiveMessage();
    if (responseMsg.type != MessageType::OT_ROUND_RESPONSE) {
      throw std::runtime_error("Expected OT_ROUND_RESPONSE, got type " +
                               std::to_string(static_cast<int>(responseMsg.type)));
    }
    if (responseMsg.point.size() != 33) {
      throw std::runtime_error("Invalid B point size: " +
                               std::to_string(responseMsg.point.size()));
    }

    std::array<uint8_t, 33> B{};
    std::memcpy(B.data(), responseMsg.point.data(), 33);

    auto [e0, e1] = otSession_.processResponse(i, B);

    ProtoMessage encMsg;
    encMsg.type = MessageType::OT_ENCRYPTED_MSGS;
    encMsg.round_index = static_cast<uint32_t>(i);
    encMsg.e0 = std::move(e0);
    encMsg.e1 = std::move(e1);
    sendMessage(encMsg);

    if (i % 64 == 0) {
      std::cout << "[Server] Completed OT round " << i << "/256" << std::endl;
    }
  }

  auto U = otSession_.computeAdditiveShare();
  std::cout << "[Server] Additive share U: " << CryptoUtils::toHex(U)
            << std::endl;

  auto vMsg = receiveMessage();
  if (vMsg.type != MessageType::SHARE_RESULT) {
    throw std::runtime_error("Expected SHARE_RESULT from client");
  }
  std::array<uint8_t, 32> V{};
  if (vMsg.share.size() == 32) {
    std::memcpy(V.data(), vMsg.share.data(), 32);
  }

  ProtoMessage uMsg;
  uMsg.type = MessageType::SHARE_RESULT;
  uMsg.share.assign(U.begin(), U.end());
  sendMessage(uMsg);

  ProtoMessage xMsg;
  xMsg.type = MessageType::SHARE_RESULT;
  xMsg.share.assign(x_.begin(), x_.end());
  sendMessage(xMsg);

  auto yMsg = receiveMessage();
  std::array<uint8_t, 32> y{};
  if (yMsg.share.size() == 32) {
    std::memcpy(y.data(), yMsg.share.data(), 32);
  }

  auto sumUV = CryptoUtils::scalarAdd(U, V);
  auto xy = CryptoUtils::scalarMul(x_, y);
  bool pass = (sumUV == xy);

  std::cout << "\n=== VERIFICATION ===" << std::endl;
  std::cout << "[Server] x           : " << CryptoUtils::toHex(x_) << std::endl;
  std::cout << "[Server] y (client)  : " << CryptoUtils::toHex(y) << std::endl;
  std::cout << "[Server] U (additive): " << CryptoUtils::toHex(U) << std::endl;
  std::cout << "[Server] V (client)  : " << CryptoUtils::toHex(V) << std::endl;
  std::cout << "[Server] U + V mod n : " << CryptoUtils::toHex(sumUV) << std::endl;
  std::cout << "[Server] x * y mod n : " << CryptoUtils::toHex(xy) << std::endl;
  std::cout << "[Server] Result      : " << (pass ? "PASS ✓" : "FAIL ✗") << std::endl;
}

void Session::sendMessage(const ProtoMessage& msg) {
  auto framed = ProtoUtils::encodeFramed(msg);
  boost::asio::write(socket_, boost::asio::buffer(framed));
}

ProtoMessage Session::receiveMessage() {
  auto lenBuf = readExact(4);
  uint32_t msgLen = ProtoUtils::readLength(lenBuf.data());

    throw std::runtime_error("Message too large: " + std::to_string(msgLen));
  }

  auto payload = readExact(msgLen);
  return ProtoUtils::decode(payload);
}

std::vector<uint8_t> Session::readExact(size_t n) {
  std::vector<uint8_t> buf(n);
  size_t total = 0;
  while (total < n) {
    boost::system::error_code ec;
    size_t bytes_read = socket_.read_some(
        boost::asio::buffer(buf.data() + total, n - total), ec);
    if (ec) {
      throw std::runtime_error("Read error: " + ec.message());
    }
    total += bytes_read;
  }
  return buf;
}


Server::Server(boost::asio::io_context& io_context, unsigned short port,
               const std::array<uint8_t, 32>& x)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), x_(x) {
  doAccept();
}

void Server::doAccept() {
  acceptor_.async_accept(
      [this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
          auto session =
              std::make_shared<Session>(std::move(socket), x_);
          session->start();
        } else {
          std::cerr << "[Server] Accept error: " << ec.message() << std::endl;
        }
        doAccept();
      });
}
