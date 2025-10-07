#include <boost/array.hpp>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

int main() {
    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 12345));

    for (;;) {
        tcp::socket socket(io);
        acceptor.accept(socket);

        for (;;) {
            boost::array<char, 128> buf;
            boost::system::error_code error;
            size_t len = socket.read_some(boost::asio::buffer(buf), error);
            if (error == boost::asio::error::eof) break;
            boost::asio::write(socket, boost::asio::buffer(buf, len));
        }
    }
}
