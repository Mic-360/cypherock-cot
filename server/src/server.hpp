#ifndef SERVER_HPP
#define SERVER_HPP

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <boost/asio.hpp>

#include "ot_session.hpp"
#include "proto_utils.hpp"

using boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
 public:
  Session(tcp::socket socket, const std::array<uint8_t, 32>& x);

  void start();

 private:
  void runProtocol();

  void sendMessage(const ProtoMessage& msg);

  [[nodiscard]] ProtoMessage receiveMessage();

  [[nodiscard]] std::vector<uint8_t> readExact(size_t n);

  tcp::socket socket_;
  OTSession otSession_;
  std::array<uint8_t, 32> x_;
};

class Server {
 public:
  Server(boost::asio::io_context& io_context, unsigned short port,
         const std::array<uint8_t, 32>& x);

 private:
  void doAccept();

  tcp::acceptor acceptor_;
  std::array<uint8_t, 32> x_;
};

#endif
