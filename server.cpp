#include <boost/asio.hpp>
#include <iostream>
#include <memory>
#include <set>
#include <mutex>
#include <deque>

using boost::asio::ip::tcp;

class ChatSession;

class ChatRoom
{
public:
    void join(const std::shared_ptr<ChatSession>& session)
    {
        std::lock_guard lock(mutex_);
        sessions_.insert(session);
        std::cout << "Client joined. Total: " << sessions_.size() << std::endl;
    }

    void leave(const std::shared_ptr<ChatSession>& session)
    {
        std::lock_guard lock(mutex_);
        sessions_.erase(session);
        std::cout << "Client left. Total: " << sessions_.size() << std::endl;
    }

    void broadcast(const std::string& message, const std::shared_ptr<ChatSession> &sender);

private:
    std::set<std::shared_ptr<ChatSession>> sessions_;
    std::mutex mutex_;
};

class ChatSession : public std::enable_shared_from_this<ChatSession>
{
public:
    ChatSession(tcp::socket socket, ChatRoom& room)
        : socket_(std::move(socket)), room_(room) {}

    void start()
    {
        room_.join(shared_from_this());
        read_message();
    }

    void deliver(const std::string& message)
    {
        const bool write_in_progress = !write_msgs_.empty();
        write_msgs_.push_back(message);

        if (!write_in_progress)
        {
            write_message();
        }
    }

private:
    void read_message()
    {
        auto self(shared_from_this());
        boost::asio::async_read_until(socket_, buffer_, '\n',
            [this, self](const boost::system::error_code &ec, std::size_t){
                if (!ec)
                {
                    std::istream is(&buffer_);
                    std::string message;
                    std::getline(is, message);

                    std::cout << "Received: " << message << std::endl;

                    room_.broadcast(message + "\n", nullptr);

                    read_message();
                }
                else
                {
                    room_.leave(shared_from_this());
                }
            });
    }

    void write_message()
    {
        auto self(shared_from_this());
        boost::asio::async_write(socket_,
            boost::asio::buffer(write_msgs_.front()),
            [this](const boost::system::error_code &ec, std::size_t) {
                if (!ec)
                {
                    write_msgs_.pop_front();
                    if (!write_msgs_.empty())
                    {
                        write_message();
                    }
                }
                else
                {
                    room_.leave(shared_from_this());
                }
            });
    }

    tcp::socket socket_;
    ChatRoom& room_;
    boost::asio::streambuf buffer_;
    std::deque<std::string> write_msgs_;
};

void ChatRoom::broadcast(const std::string& message, const std::shared_ptr<ChatSession> &sender)
{
    std::lock_guard lock(mutex_);
    for (auto& session : sessions_)
    {
        if (!sender || session != sender)
        {
            session->deliver(message);
        }
    }
}

class ChatServer
{
public:
    ChatServer(boost::asio::io_context& io, const short port)
        : acceptor_(io, tcp::endpoint(tcp::v4(), port))
    {
        accept();
    }

private:
    void accept()
    {
        acceptor_.async_accept(
            [this](const boost::system::error_code &ec, tcp::socket socket) {
                if (!ec)
                {
                    std::cout << "New connection accepted" << std::endl;
                    std::make_shared<ChatSession>(std::move(socket), room_)->start();
                }
                accept();
            });
    }

    tcp::acceptor acceptor_;
    ChatRoom room_;
};

int main(const int argc, char* argv[])
{
    try
    {
        int port = 12345;
        if (argc > 1)
        {
            port = std::atoi(argv[1]);
        }

        boost::asio::io_context io;
        ChatServer server(io, port);

        std::cout << "Chat server started on port " << port << std::endl;
        std::cout << "Waiting for connections..." << std::endl;

        io.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}