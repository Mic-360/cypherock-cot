// entry for cot-mta server (alice)

// rolls a random x, starts boost asio on port 12345, waits for bob
// each connection runs the 256-round ot protocol

#include <iostream>

#include <boost/asio.hpp>

#include "crypto_utils.hpp"
#include "server.hpp"

int main() {
  try {
    auto x = CryptoUtils::generateScalar();
    std::cout << "[Server] Multiplicative share x: " << CryptoUtils::toHex(x)
              << std::endl;

    boost::asio::io_context io_context;
    Server server(io_context, 12345, x);

    std::cout << "[Server] Listening on port 12345..." << std::endl;
    io_context.run();

  } catch (const std::exception& e) {
    std::cerr << "[Server] Fatal error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
