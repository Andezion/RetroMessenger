#include <wx/wx.h>
#include <wx/listbox.h>
#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <thread>
#include <memory>

#include <map>
#include <deque>
#include <mutex>
#include <sodium.h>
#include <zstd.h>
#include <vector>
#include <cstring>

using boost::asio::ip::tcp;

wxDECLARE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_PEER_DISCONNECTED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_DISCONNECTED, wxCommandEvent);

static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::string out(len * 2, '\0');
    sodium_bin2hex(&out[0], out.size() + 1, data, len);
    return out;
}

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> out(hex.size() / 2);
    size_t bin_len = 0;
    sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(),
                   nullptr, &bin_len, nullptr);
    out.resize(bin_len);
    return out;
}

static const size_t COMPRESS_THRESHOLD = 64;

static std::vector<unsigned char> compress_data(const std::string& input) {
    if (input.size() < COMPRESS_THRESHOLD) {
        std::vector<unsigned char> out(1 + input.size());
        out[0] = 0x00;
        std::memcpy(out.data() + 1, input.data(), input.size());
        return out;
    }
    size_t bound = ZSTD_compressBound(input.size());
    std::vector<unsigned char> out(1 + bound);
    out[0] = 0x01; 
    size_t compressed_size = ZSTD_compress(out.data() + 1, bound,
                                           input.data(), input.size(), 3);
    if (ZSTD_isError(compressed_size)) {
        out.resize(1 + input.size());
        out[0] = 0x00;
        std::memcpy(out.data() + 1, input.data(), input.size());
        return out;
    }
    out.resize(1 + compressed_size);
    return out;
}

static std::string decompress_data(const unsigned char* data, size_t len) {
    if (len == 0) return "";
    if (data[0] == 0x00) {
        return std::string(reinterpret_cast<const char*>(data + 1), len - 1);
    }
    unsigned long long decompressed_size = ZSTD_getFrameContentSize(data + 1, len - 1);
    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN || decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        decompressed_size = len * 10;
    }
    std::vector<char> out(decompressed_size);
    size_t result = ZSTD_decompress(out.data(), out.size(), data + 1, len - 1);
    if (ZSTD_isError(result)) {
        return "[decompression error]";
    }
    return std::string(out.data(), result);
}

static const size_t PAD_BLOCK_SIZE = 256;

static std::vector<unsigned char> pad_data(const std::vector<unsigned char>& input) {
    size_t padded_len = ((input.size() / PAD_BLOCK_SIZE) + 1) * PAD_BLOCK_SIZE;
    std::vector<unsigned char> out(padded_len);
    std::memcpy(out.data(), input.data(), input.size());
    out[input.size()] = 0x80;
    for (size_t i = input.size() + 1; i < padded_len; ++i) {
        out[i] = 0x00;
    }
    return out;
}

static std::vector<unsigned char> unpad_data(const std::vector<unsigned char>& input) {
    if (input.empty()) return {};
    size_t i = input.size();
    while (i > 0) {
        --i;
        if (input[i] == 0x80) {
            return std::vector<unsigned char>(input.begin(), input.begin() + i);
        }
        if (input[i] != 0x00) {
            return input;
        }
    }
    return input;
}

static std::vector<unsigned char> encrypt_message(
    const std::vector<unsigned char>& plaintext,
    const unsigned char shared_key[crypto_box_BEFORENMBYTES])
{
    std::vector<unsigned char> nonce(crypto_box_NONCEBYTES);
    randombytes_buf(nonce.data(), crypto_box_NONCEBYTES);

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_box_MACBYTES);
    crypto_box_easy_afternm(ciphertext.data(), plaintext.data(), plaintext.size(),
                            nonce.data(), shared_key);

    std::vector<unsigned char> out(nonce.size() + ciphertext.size());
    std::memcpy(out.data(), nonce.data(), nonce.size());
    std::memcpy(out.data() + nonce.size(), ciphertext.data(), ciphertext.size());
    return out;
}

static std::vector<unsigned char> decrypt_message(
    const unsigned char* data, size_t len,
    const unsigned char shared_key[crypto_box_BEFORENMBYTES])
{
    if (len < crypto_box_NONCEBYTES + crypto_box_MACBYTES) return {};

    const unsigned char* nonce = data;
    const unsigned char* ciphertext = data + crypto_box_NONCEBYTES;
    size_t ciphertext_len = len - crypto_box_NONCEBYTES;

    std::vector<unsigned char> plaintext(ciphertext_len - crypto_box_MACBYTES);
    if (crypto_box_open_easy_afternm(plaintext.data(), ciphertext, ciphertext_len,
                                      nonce, shared_key) != 0) {
        return {}; 
    }
    return plaintext;
}

static std::vector<unsigned char> seal_message(
    const std::string& message,
    const unsigned char shared_key[crypto_box_BEFORENMBYTES])
{
    auto compressed = compress_data(message);
    auto padded = pad_data(compressed);
    return encrypt_message(padded, shared_key);
}

static std::string unseal_message(
    const unsigned char* data, size_t len,
    const unsigned char shared_key[crypto_box_BEFORENMBYTES])
{
    auto decrypted = decrypt_message(data, len, shared_key);
    if (decrypted.empty()) return "[decryption failed]";
    auto unpadded = unpad_data(decrypted);
    return decompress_data(unpadded.data(), unpadded.size());
}

std::string generateUniqueID() {
    unsigned char buf[16]; 
    randombytes_buf(buf, sizeof(buf));
    return bytes_to_hex(buf, sizeof(buf));
}

std::string truncateID(const std::string& id) {
    if (id.size() <= 12) return id;
    return id.substr(0, 6) + ".." + id.substr(id.size() - 6);
}

enum class ConnectionMode {
    PEER_TO_PEER,
    SERVER
};

struct ChatInfo {
    std::string chatID;
    std::string peerID;
    std::string localAlias;
    std::vector<std::pair<std::string, std::string>> messageCache; 
    unsigned char shared_key[crypto_box_BEFORENMBYTES];
    bool active;
};

static std::vector<unsigned char> frame_encode(const std::vector<unsigned char>& payload) {
    uint32_t len = static_cast<uint32_t>(payload.size());
    std::vector<unsigned char> frame(4 + payload.size());
    frame[0] = (len >> 24) & 0xFF;
    frame[1] = (len >> 16) & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    std::memcpy(frame.data() + 4, payload.data(), payload.size());
    return frame;
}

static std::vector<unsigned char> frame_encode_string(const std::string& s) {
    std::vector<unsigned char> payload(s.begin(), s.end());
    return frame_encode(payload);
}

class P2PSession : public std::enable_shared_from_this<P2PSession> {
public:
    P2PSession(tcp::socket socket, wxEvtHandler* handler, const std::string& chatID,
               const unsigned char shared_key[crypto_box_BEFORENMBYTES])
        : socket_(std::move(socket)), event_handler_(handler), chat_id_(chatID)
    {
        std::memcpy(shared_key_, shared_key, crypto_box_BEFORENMBYTES);
    }

    void start() {
        read_frame_header();
    }

    void send_message(const std::string& message) {
        auto encrypted = seal_message(message, shared_key_);
        auto frame = frame_encode(encrypted);

        auto self(shared_from_this());
        boost::asio::post(socket_.get_executor(), [this, self, frame]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(frame);
            if (!write_in_progress) {
                do_write();
            }
        });
    }

    std::string get_chat_id() const { return chat_id_; }

private:
    void read_frame_header() {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(header_buf_, 4),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    uint32_t len = (static_cast<uint32_t>(header_buf_[0]) << 24) |
                                   (static_cast<uint32_t>(header_buf_[1]) << 16) |
                                   (static_cast<uint32_t>(header_buf_[2]) << 8) |
                                   static_cast<uint32_t>(header_buf_[3]);

                    if (len > 10 * 1024 * 1024) { 
                        notify_disconnect();
                        return;
                    }
                    payload_buf_.resize(len);
                    read_frame_payload(len);
                } else {
                    notify_disconnect();
                }
            });
    }

    void read_frame_payload(uint32_t len) {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(payload_buf_.data(), len),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    auto message = unseal_message(payload_buf_.data(), payload_buf_.size(), shared_key_);

                    if (event_handler_) {
                        wxCommandEvent event(wxEVT_MESSAGE_RECEIVED);
                        event.SetString(wxString::FromUTF8(message));
                        event.SetClientData(new std::string(chat_id_));
                        wxQueueEvent(event_handler_, event.Clone());
                    }

                    read_frame_header();
                } else {
                    notify_disconnect();
                }
            });
    }

    void do_write() {
        auto self(shared_from_this());
        boost::asio::async_write(socket_,
            boost::asio::buffer(write_queue_.front()),
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    write_queue_.pop_front();
                    if (!write_queue_.empty()) {
                        do_write();
                    }
                } else {
                    notify_disconnect();
                }
            });
    }

    void notify_disconnect() {
        if (event_handler_) {
            wxCommandEvent event(wxEVT_PEER_DISCONNECTED);
            event.SetClientData(new std::string(chat_id_));
            wxQueueEvent(event_handler_, event.Clone());
        }
    }

    tcp::socket socket_;
    wxEvtHandler* event_handler_;
    std::string chat_id_;
    unsigned char shared_key_[crypto_box_BEFORENMBYTES];
    unsigned char header_buf_[4];
    std::vector<unsigned char> payload_buf_;
    std::deque<std::vector<unsigned char>> write_queue_;
};

class P2PManager {
public:
    P2PManager(wxEvtHandler* handler,
               const unsigned char* my_pk, const unsigned char* my_sk,
               unsigned short port = 0)
        : event_handler_(handler),
          acceptor_(io_context_),
          listening_port_(port)
    {
        std::memcpy(my_pk_, my_pk, crypto_box_PUBLICKEYBYTES);
        std::memcpy(my_sk_, my_sk, crypto_box_SECRETKEYBYTES);

        if (port == 0) {
            listening_port_ = find_available_port();
        }

        tcp::endpoint endpoint(tcp::v4(), listening_port_);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();

        start_accept();
        io_thread_ = std::thread([this]() { io_context_.run(); });
    }

    ~P2PManager() {
        io_context_.stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
    }

    unsigned short get_listening_port() const { return listening_port_; }

    void send_invitation(const std::string& peer_address, const std::string& peer_port,
                         const std::string& my_id) {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context_);

        try {
            tcp::resolver resolver(io_context_);
            auto endpoints = resolver.resolve(peer_address, peer_port);
            boost::asio::connect(*socket, endpoints);

            socket->non_blocking(false);

            std::string pk_hex = bytes_to_hex(my_pk_, crypto_box_PUBLICKEYBYTES);
            std::string invite_msg = "INVITE:" + pk_hex + ":" + my_id + "\n";
            boost::asio::write(*socket, boost::asio::buffer(invite_msg));

            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(socket->native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            boost::asio::streambuf buffer;
            boost::asio::read_until(*socket, buffer, '\n');
            std::istream is(&buffer);
            std::string response;
            std::getline(is, response);

            if (response.substr(0, 6) == "ACCEPT") {
                size_t pos1 = response.find(':', 7);
                std::string peer_pk_hex = response.substr(7, pos1 - 7);
                std::string peer_id = response.substr(pos1 + 1);

                auto peer_pk = hex_to_bytes(peer_pk_hex);
                if (peer_pk.size() != crypto_box_PUBLICKEYBYTES) {
                    wxLogError("Invalid peer public key size");
                    return;
                }

                unsigned char shared_key[crypto_box_BEFORENMBYTES];
                if (crypto_box_beforenm(shared_key, peer_pk.data(), my_sk_) != 0) {
                    wxLogError("Failed to compute shared key");
                    return;
                }

                std::string chat_id = generateUniqueID();
                auto session = std::make_shared<P2PSession>(std::move(*socket), event_handler_,
                                                             chat_id, shared_key);
                {
                    std::lock_guard<std::mutex> lock(sessions_mutex_);
                    sessions_[chat_id] = session;
                }
                session->start();

                std::string sk_hex = bytes_to_hex(shared_key, crypto_box_BEFORENMBYTES);
                wxCommandEvent event(wxEVT_PEER_CONNECTED);
                event.SetString(wxString::Format("%s;%s;%s", chat_id, peer_id, sk_hex));
                wxQueueEvent(event_handler_, event.Clone());
            }
        } catch (const std::exception& e) {
            wxLogError("Failed to send invitation: %s", e.what());
        }
    }

    void send_message(const std::string& chat_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(chat_id);
        if (it != sessions_.end()) {
            it->second->send_message(message);
        }
    }

    void add_session(const std::string& chat_id, std::shared_ptr<P2PSession> session) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[chat_id] = session;
    }

    void close_chat(const std::string& chat_id) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.erase(chat_id);
    }

    int store_pending_socket(tcp::socket socket) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        int id = next_pending_id_++;
        pending_sockets_.emplace(id, std::move(socket));
        return id;
    }

    tcp::socket take_pending_socket(int id) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_sockets_.find(id);
        if (it != pending_sockets_.end()) {
            tcp::socket s = std::move(it->second);
            pending_sockets_.erase(it);
            return s;
        }
        throw std::runtime_error("Pending socket not found");
    }

private:
    unsigned short find_available_port() {
        tcp::acceptor acc(io_context_, tcp::endpoint(tcp::v4(), 0));
        unsigned short port = acc.local_endpoint().port();
        acc.close();
        return port;
    }

    void start_accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket,
            [this, socket](const boost::system::error_code& ec) {
                if (!ec) {
                    handle_new_connection(std::move(*socket));
                }
                do_accept();
            });
    }

    void handle_new_connection(tcp::socket socket) {
        try {
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            boost::asio::streambuf buffer;
            boost::asio::read_until(socket, buffer, '\n');
            std::istream is(&buffer);
            std::string invite_msg;
            std::getline(is, invite_msg);

            if (invite_msg.substr(0, 6) == "INVITE") {
                size_t pos1 = invite_msg.find(':', 7);
                std::string peer_pk_hex = invite_msg.substr(7, pos1 - 7);
                std::string peer_id = invite_msg.substr(pos1 + 1);

                int pending_id = store_pending_socket(std::move(socket));

                wxCommandEvent event(wxEVT_INVITATION_RECEIVED);
                event.SetString(wxString::Format("%s;%s;%d", peer_id, peer_pk_hex, pending_id));
                wxQueueEvent(event_handler_, event.Clone());
            }
        } catch (const std::exception& e) {
            wxLogError("Error handling connection: %s", e.what());
        }
    }

    void do_accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket,
            [this, socket](const boost::system::error_code& ec) {
                if (!ec) {
                    handle_new_connection(std::move(*socket));
                }
                do_accept();
            });
    }

    wxEvtHandler* event_handler_;
    boost::asio::io_context io_context_;
    tcp::acceptor acceptor_;
    unsigned short listening_port_;
    std::thread io_thread_;

    unsigned char my_pk_[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk_[crypto_box_SECRETKEYBYTES];

    std::map<std::string, std::shared_ptr<P2PSession>> sessions_;
    std::mutex sessions_mutex_;

    std::map<int, tcp::socket> pending_sockets_;
    std::mutex pending_mutex_;
    int next_pending_id_ = 0;
};

class ServerClient {
public:
    ServerClient() : socket_(io_context_), event_handler_(nullptr) {}

    ~ServerClient() {
        disconnect();
    }

    bool connect(const std::string& host, const std::string& port, wxEvtHandler* handler) {
        try {
            event_handler_ = handler;
            tcp::resolver resolver(io_context_);
            auto endpoints = resolver.resolve(host, port);
            boost::asio::connect(socket_, endpoints);

            start_read();
            io_thread_ = std::thread([this]() { io_context_.run(); });

            return true;
        } catch (const std::exception& e) {
            wxLogError("Connection error: %s", e.what());
            return false;
        }
    }

    void send(const std::string& message) {
        try {
            std::string msg = message + "\n";
            boost::asio::async_write(socket_, boost::asio::buffer(msg),
                [](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        wxLogError("Send error: %s", ec.message().c_str());
                    }
                });
        } catch (const std::exception& e) {
            wxLogError("Send error: %s", e.what());
        }
    }

    void disconnect() {
        boost::asio::post(io_context_, [this]() {
            if (socket_.is_open()) {
                socket_.close();
            }
        });

        if (io_thread_.joinable()) {
            io_thread_.join();
        }
    }

private:
    void start_read() {
        boost::asio::async_read_until(socket_, buffer_, '\n',
            [this](const boost::system::error_code& error, std::size_t) {
                if (!error) {
                    std::istream is(&buffer_);
                    std::string message;
                    std::getline(is, message);

                    if (event_handler_) {
                        wxCommandEvent event(wxEVT_MESSAGE_RECEIVED);
                        event.SetString(wxString::FromUTF8(message));
                        wxQueueEvent(event_handler_, event.Clone());
                    }

                    start_read();
                } else if (error != boost::asio::error::operation_aborted) {
                    wxLogError("Read error: %s", error.message().c_str());
                }
            });
    }

    boost::asio::io_context io_context_;
    tcp::socket socket_;
    wxEvtHandler* event_handler_;
    boost::asio::streambuf buffer_;
    std::thread io_thread_;
};


class SettingsDialog : public wxDialog {
public:
    SettingsDialog(wxWindow* parent, ConnectionMode current_mode)
        : wxDialog(parent, wxID_ANY, "Settings", wxDefaultPosition, wxSize(400, 250)) {

        auto* sizer = new wxBoxSizer(wxVERTICAL);

        sizer->Add(new wxStaticText(this, wxID_ANY, "Connection Mode:"), 0, wxALL, 10);

        wxArrayString modes;
        modes.Add("Peer-to-Peer (No Server)");
        modes.Add("Server Mode");

        mode_choice_ = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, modes);
        mode_choice_->SetSelection(current_mode == ConnectionMode::PEER_TO_PEER ? 0 : 1);
        sizer->Add(mode_choice_, 0, wxEXPAND | wxALL, 10);

        server_panel_ = new wxPanel(this);
        auto* server_sizer = new wxBoxSizer(wxVERTICAL);

        auto* host_sizer = new wxBoxSizer(wxHORIZONTAL);
        host_sizer->Add(new wxStaticText(server_panel_, wxID_ANY, "Server Host:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        server_host_ = new wxTextCtrl(server_panel_, wxID_ANY, "127.0.0.1");
        host_sizer->Add(server_host_, 1, wxEXPAND);
        server_sizer->Add(host_sizer, 0, wxEXPAND | wxALL, 5);

        auto* port_sizer = new wxBoxSizer(wxHORIZONTAL);
        port_sizer->Add(new wxStaticText(server_panel_, wxID_ANY, "Server Port:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        server_port_ = new wxTextCtrl(server_panel_, wxID_ANY, "12345");
        port_sizer->Add(server_port_, 1, wxEXPAND);
        server_sizer->Add(port_sizer, 0, wxEXPAND | wxALL, 5);

        server_panel_->SetSizer(server_sizer);
        sizer->Add(server_panel_, 0, wxEXPAND | wxALL, 10);

        server_panel_->Enable(current_mode == ConnectionMode::SERVER);

        mode_choice_->Bind(wxEVT_CHOICE, [this](wxCommandEvent&) {
            server_panel_->Enable(mode_choice_->GetSelection() == 1);
        });

        auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);
        auto* ok_btn = new wxButton(this, wxID_OK, "OK");
        auto* cancel_btn = new wxButton(this, wxID_CANCEL, "Cancel");
        button_sizer->Add(ok_btn, 0, wxALL, 5);
        button_sizer->Add(cancel_btn, 0, wxALL, 5);
        sizer->Add(button_sizer, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizer(sizer);
        Centre();
    }

    ConnectionMode get_mode() const {
        return mode_choice_->GetSelection() == 0 ? ConnectionMode::PEER_TO_PEER : ConnectionMode::SERVER;
    }

    std::string get_server_host() const { return server_host_->GetValue().ToStdString(); }
    std::string get_server_port() const { return server_port_->GetValue().ToStdString(); }

private:
    wxChoice* mode_choice_;
    wxPanel* server_panel_;
    wxTextCtrl* server_host_;
    wxTextCtrl* server_port_;
};


class NewChatDialog : public wxDialog {
public:
    NewChatDialog(wxWindow* parent)
        : wxDialog(parent, wxID_ANY, "Start New Chat", wxDefaultPosition, wxSize(450, 280)) {

        auto* sizer = new wxBoxSizer(wxVERTICAL);

        sizer->Add(new wxStaticText(this, wxID_ANY, "Enter peer address and port to connect:"), 0, wxALL, 10);

        auto* address_sizer = new wxBoxSizer(wxHORIZONTAL);
        address_sizer->Add(new wxStaticText(this, wxID_ANY, "Address:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        address_input_ = new wxTextCtrl(this, wxID_ANY, "127.0.0.1");
        address_sizer->Add(address_input_, 1, wxEXPAND);
        sizer->Add(address_sizer, 0, wxEXPAND | wxALL, 10);

        auto* port_sizer = new wxBoxSizer(wxHORIZONTAL);
        port_sizer->Add(new wxStaticText(this, wxID_ANY, "Port:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        port_input_ = new wxTextCtrl(this, wxID_ANY, "12345");
        port_sizer->Add(port_input_, 1, wxEXPAND);
        sizer->Add(port_sizer, 0, wxEXPAND | wxALL, 10);

        auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);
        auto* invite_btn = new wxButton(this, wxID_OK, "Connect");
        auto* cancel_btn = new wxButton(this, wxID_CANCEL, "Cancel");
        button_sizer->Add(invite_btn, 0, wxALL, 5);
        button_sizer->Add(cancel_btn, 0, wxALL, 5);
        sizer->Add(button_sizer, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizer(sizer);
        Centre();
    }

    std::string get_address() const { return address_input_->GetValue().ToStdString(); }
    std::string get_port() const { return port_input_->GetValue().ToStdString(); }

private:
    wxTextCtrl* address_input_;
    wxTextCtrl* port_input_;
};


class AliasDialog : public wxDialog {
public:
    AliasDialog(wxWindow* parent, const std::string& peer_id)
        : wxDialog(parent, wxID_ANY, "Set Alias", wxDefaultPosition, wxSize(400, 180)) {

        auto* sizer = new wxBoxSizer(wxVERTICAL);

        sizer->Add(new wxStaticText(this, wxID_ANY,
            "Set a local alias for peer " + truncateID(peer_id) + ":"), 0, wxALL, 10);

        alias_input_ = new wxTextCtrl(this, wxID_ANY);
        sizer->Add(alias_input_, 0, wxEXPAND | wxALL, 10);

        auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);
        button_sizer->Add(new wxButton(this, wxID_OK, "OK"), 0, wxALL, 5);
        button_sizer->Add(new wxButton(this, wxID_CANCEL, "Cancel"), 0, wxALL, 5);
        sizer->Add(button_sizer, 0, wxALIGN_CENTER | wxALL, 10);

        SetSizer(sizer);
        Centre();
    }

    std::string get_alias() const { return alias_input_->GetValue().ToStdString(); }

private:
    wxTextCtrl* alias_input_;
};

class MyFrame : public wxFrame {
public:
    MyFrame(const wxString& title);
    ~MyFrame();

private:
    wxStaticText* user_id_label_;
    wxStaticText* port_label_;
    wxListBox* chat_list_;
    wxTextCtrl* chat_display_;
    wxTextCtrl* message_input_;
    wxButton* send_button_;
    wxButton* new_chat_button_;
    wxButton* settings_button_;
    wxButton* end_chat_button_;

    std::string current_user_id_;
    ConnectionMode connection_mode_;
    std::map<std::string, ChatInfo> chats_;
    std::string active_chat_id_;

    unsigned char my_pk_[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk_[crypto_box_SECRETKEYBYTES];

    std::unique_ptr<P2PManager> p2p_manager_;
    std::unique_ptr<ServerClient> server_client_;
    bool connected_;

    void OnNewChat(wxCommandEvent& event);
    void OnSend(wxCommandEvent& event);
    void OnSettings(wxCommandEvent& event);
    void OnEndChat(wxCommandEvent& event);
    void OnChatSelected(wxCommandEvent& event);
    void OnMessageReceived(wxCommandEvent& event);
    void OnInvitationReceived(wxCommandEvent& event);
    void OnPeerConnected(wxCommandEvent& event);
    void OnPeerDisconnected(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);
    void OnChatListDClick(wxCommandEvent& event);

    void UpdateUI();
    void RefreshChatList();
    void LoadChatMessages(const std::string& chat_id);
    void RegenerateUserID();
    void RegenerateKeypair();
    std::string GetChatDisplayName(const ChatInfo& info) const;

    wxDECLARE_EVENT_TABLE();
};

enum {
    ID_Send = wxID_HIGHEST + 1,
    ID_NewChat,
    ID_Settings,
    ID_EndChat,
    ID_ChatList
};

wxBEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_BUTTON(ID_Send, MyFrame::OnSend)
    EVT_BUTTON(ID_NewChat, MyFrame::OnNewChat)
    EVT_BUTTON(ID_Settings, MyFrame::OnSettings)
    EVT_BUTTON(ID_EndChat, MyFrame::OnEndChat)
    EVT_LISTBOX(ID_ChatList, MyFrame::OnChatSelected)
    EVT_LISTBOX_DCLICK(ID_ChatList, MyFrame::OnChatListDClick)
    EVT_COMMAND(wxID_ANY, wxEVT_MESSAGE_RECEIVED, MyFrame::OnMessageReceived)
    EVT_COMMAND(wxID_ANY, wxEVT_INVITATION_RECEIVED, MyFrame::OnInvitationReceived)
    EVT_COMMAND(wxID_ANY, wxEVT_PEER_CONNECTED, MyFrame::OnPeerConnected)
    EVT_COMMAND(wxID_ANY, wxEVT_PEER_DISCONNECTED, MyFrame::OnPeerDisconnected)
    EVT_CLOSE(MyFrame::OnClose)
wxEND_EVENT_TABLE()

class MyApp : public wxApp {
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(MyApp);

bool MyApp::OnInit() {
    if (sodium_init() < 0) {
        wxMessageBox("Failed to initialize libsodium!", "Fatal Error", wxOK | wxICON_ERROR);
        return false;
    }
    auto* frame = new MyFrame("RetroMessenger - P2P Encrypted");
    frame->Show(true);
    return true;
}

MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(900, 600)),
      connection_mode_(ConnectionMode::PEER_TO_PEER),
      connected_(false) {

    current_user_id_ = generateUniqueID();
    RegenerateKeypair();

    auto* main_sizer = new wxBoxSizer(wxVERTICAL);

    auto* top_bar = new wxPanel(this);
    auto* top_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto* info_sizer = new wxBoxSizer(wxVERTICAL);
    user_id_label_ = new wxStaticText(top_bar, wxID_ANY, "Your ID: " + current_user_id_);
    info_sizer->Add(user_id_label_, 0, wxALL, 5);
    port_label_ = new wxStaticText(top_bar, wxID_ANY, "Port: ...");
    info_sizer->Add(port_label_, 0, wxALL, 5);
    top_sizer->Add(info_sizer, 1, wxEXPAND);

    settings_button_ = new wxButton(top_bar, ID_Settings, "Settings");
    top_sizer->Add(settings_button_, 0, wxALL, 5);

    top_bar->SetSizer(top_sizer);
    main_sizer->Add(top_bar, 0, wxEXPAND | wxALL, 5);

    auto* content_sizer = new wxBoxSizer(wxHORIZONTAL);

    auto* left_panel = new wxPanel(this);
    auto* left_sizer = new wxBoxSizer(wxVERTICAL);

    new_chat_button_ = new wxButton(left_panel, ID_NewChat, "+ Start New Chat");
    left_sizer->Add(new_chat_button_, 0, wxEXPAND | wxALL, 5);

    left_sizer->Add(new wxStaticText(left_panel, wxID_ANY, "Active Chats:"), 0, wxALL, 5);
    chat_list_ = new wxListBox(left_panel, ID_ChatList);
    left_sizer->Add(chat_list_, 1, wxEXPAND | wxALL, 5);

    left_sizer->Add(new wxStaticText(left_panel, wxID_ANY, "(Double-click chat to set alias)"), 0, wxLEFT | wxBOTTOM, 5);

    end_chat_button_ = new wxButton(left_panel, ID_EndChat, "End Chat");
    end_chat_button_->Enable(false);
    left_sizer->Add(end_chat_button_, 0, wxEXPAND | wxALL, 5);

    left_panel->SetSizer(left_sizer);
    content_sizer->Add(left_panel, 1, wxEXPAND | wxALL, 5);

    auto* right_panel = new wxPanel(this);
    auto* right_sizer = new wxBoxSizer(wxVERTICAL);

    chat_display_ = new wxTextCtrl(right_panel, wxID_ANY, "",
                                    wxDefaultPosition, wxDefaultSize,
                                    wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    right_sizer->Add(chat_display_, 1, wxEXPAND | wxALL, 5);

    auto* input_sizer = new wxBoxSizer(wxHORIZONTAL);
    message_input_ = new wxTextCtrl(right_panel, wxID_ANY, "",
                                     wxDefaultPosition, wxDefaultSize,
                                     wxTE_PROCESS_ENTER);
    message_input_->Enable(false);
    input_sizer->Add(message_input_, 1, wxEXPAND | wxALL, 5);

    send_button_ = new wxButton(right_panel, ID_Send, "Send");
    send_button_->Enable(false);
    input_sizer->Add(send_button_, 0, wxALL, 5);

    right_sizer->Add(input_sizer, 0, wxEXPAND);
    right_panel->SetSizer(right_sizer);
    content_sizer->Add(right_panel, 2, wxEXPAND | wxALL, 5);

    main_sizer->Add(content_sizer, 1, wxEXPAND);

    SetSizer(main_sizer);
    Centre();

    message_input_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent&) {
        if (!active_chat_id_.empty()) {
            wxCommandEvent dummy;
            OnSend(dummy);
        }
    });

    p2p_manager_ = std::make_unique<P2PManager>(this, my_pk_, my_sk_);
    port_label_->SetLabel(wxString::Format("Port: %d", p2p_manager_->get_listening_port()));

    UpdateUI();
}

MyFrame::~MyFrame() {
    p2p_manager_.reset();
    server_client_.reset();
    sodium_memzero(my_sk_, sizeof(my_sk_));
    sodium_memzero(my_pk_, sizeof(my_pk_));
}

void MyFrame::OnNewChat(wxCommandEvent& event) {
    if (connection_mode_ == ConnectionMode::PEER_TO_PEER) {
        NewChatDialog dialog(this);
        if (dialog.ShowModal() == wxID_OK) {
            std::string peer_address = dialog.get_address();
            std::string peer_port = dialog.get_port();

            if (!peer_address.empty() && !peer_port.empty()) {
                p2p_manager_->send_invitation(peer_address, peer_port, current_user_id_);
                wxMessageBox("Invitation sent to " + peer_address + ":" + peer_port,
                             "Info", wxOK | wxICON_INFORMATION);
            }
        }
    } else {
        wxMessageBox("Server mode not fully implemented in this version",
                     "Info", wxOK | wxICON_INFORMATION);
    }
}

void MyFrame::OnSend(wxCommandEvent& event) {
    wxString message = message_input_->GetValue();
    if (message.IsEmpty() || active_chat_id_.empty()) {
        return;
    }

    std::string msg = message.ToStdString();

    if (connection_mode_ == ConnectionMode::PEER_TO_PEER) {
        p2p_manager_->send_message(active_chat_id_, msg);
    } else {
        if (server_client_) {
            server_client_->send(msg);
        }
    }

    auto& chat = chats_[active_chat_id_];
    chat.messageCache.push_back({truncateID(current_user_id_), msg});

    chat_display_->AppendText(truncateID(current_user_id_) + ": " + message + "\n");
    message_input_->Clear();
}

void MyFrame::OnSettings(wxCommandEvent& event) {
    SettingsDialog dialog(this, connection_mode_);
    if (dialog.ShowModal() == wxID_OK) {
        ConnectionMode new_mode = dialog.get_mode();

        if (new_mode != connection_mode_) {
            connection_mode_ = new_mode;

            if (connection_mode_ == ConnectionMode::PEER_TO_PEER) {
                server_client_.reset();
                if (!p2p_manager_) {
                    p2p_manager_ = std::make_unique<P2PManager>(this, my_pk_, my_sk_);
                    port_label_->SetLabel(wxString::Format("Port: %d", p2p_manager_->get_listening_port()));
                }
                SetTitle("RetroMessenger - P2P Encrypted");
            } else {
                p2p_manager_.reset();
                server_client_ = std::make_unique<ServerClient>();

                std::string host = dialog.get_server_host();
                std::string port = dialog.get_server_port();

                if (server_client_->connect(host, port, this)) {
                    connected_ = true;
                    SetTitle("RetroMessenger - Server Mode");
                    wxMessageBox("Connected to server", "Success", wxOK | wxICON_INFORMATION);
                } else {
                    wxMessageBox("Failed to connect to server", "Error", wxOK | wxICON_ERROR);
                }
            }

            UpdateUI();
        }
    }
}

void MyFrame::OnEndChat(wxCommandEvent& event) {
    if (active_chat_id_.empty()) {
        return;
    }

    int answer = wxMessageBox("Are you sure you want to end this chat? Message history will be deleted.",
                             "Confirm", wxYES_NO | wxICON_QUESTION);

    if (answer == wxYES) {
        if (connection_mode_ == ConnectionMode::PEER_TO_PEER) {
            p2p_manager_->close_chat(active_chat_id_);
        }

        auto it = chats_.find(active_chat_id_);
        if (it != chats_.end()) {
            sodium_memzero(it->second.shared_key, sizeof(it->second.shared_key));
        }

        chats_.erase(active_chat_id_);
        active_chat_id_.clear();

        RegenerateUserID();
        RegenerateKeypair();

        RefreshChatList();
        chat_display_->Clear();
        message_input_->Enable(false);
        send_button_->Enable(false);
        end_chat_button_->Enable(false);
    }
}

void MyFrame::OnChatSelected(wxCommandEvent& event) {
    int selection = chat_list_->GetSelection();
    if (selection != wxNOT_FOUND) {
        int idx = 0;
        for (const auto& [chat_id, chat_info] : chats_) {
            if (chat_info.active) {
                if (idx == selection) {
                    active_chat_id_ = chat_id;
                    LoadChatMessages(chat_id);
                    message_input_->Enable(true);
                    send_button_->Enable(true);
                    end_chat_button_->Enable(true);
                    break;
                }
                ++idx;
            }
        }
    }
}

void MyFrame::OnChatListDClick(wxCommandEvent& event) {
    if (active_chat_id_.empty()) return;
    auto it = chats_.find(active_chat_id_);
    if (it == chats_.end()) return;

    AliasDialog dialog(this, it->second.peerID);
    if (dialog.ShowModal() == wxID_OK) {
        std::string alias = dialog.get_alias();
        if (!alias.empty()) {
            it->second.localAlias = alias;
            RefreshChatList();
        }
    }
}

void MyFrame::OnMessageReceived(wxCommandEvent& event) {
    wxString message = event.GetString();
    std::string* chat_id_ptr = static_cast<std::string*>(event.GetClientData());

    if (chat_id_ptr) {
        std::string chat_id = *chat_id_ptr;
        delete chat_id_ptr;

        auto it = chats_.find(chat_id);
        if (it != chats_.end()) {
            std::string sender_display = truncateID(it->second.peerID);
            it->second.messageCache.push_back({sender_display, message.ToStdString()});

            if (chat_id == active_chat_id_) {
                chat_display_->AppendText(sender_display + ": " + message + "\n");
            }
        }
    }
}

void MyFrame::OnInvitationReceived(wxCommandEvent& event) {
    wxString data = event.GetString();
    wxArrayString parts = wxSplit(data, ';');

    if (parts.GetCount() >= 3) {
        std::string peer_id = parts[0].ToStdString();
        std::string peer_pk_hex = parts[1].ToStdString();
        int pending_socket_id = 0;
        parts[2].ToLong(reinterpret_cast<long*>(&pending_socket_id));

        int answer = wxMessageBox(
            "Peer " + truncateID(peer_id) + " wants to start an encrypted chat. Accept?",
            "Chat Invitation", wxYES_NO | wxICON_QUESTION);

        if (answer == wxYES) {
            try {
                auto socket = p2p_manager_->take_pending_socket(pending_socket_id);

                std::string pk_hex = bytes_to_hex(my_pk_, crypto_box_PUBLICKEYBYTES);
                std::string accept_msg = "ACCEPT:" + pk_hex + ":" + current_user_id_ + "\n";
                boost::asio::write(socket, boost::asio::buffer(accept_msg));

                auto peer_pk = hex_to_bytes(peer_pk_hex);
                if (peer_pk.size() != crypto_box_PUBLICKEYBYTES) {
                    wxLogError("Invalid peer public key");
                    return;
                }
                unsigned char shared_key[crypto_box_BEFORENMBYTES];
                if (crypto_box_beforenm(shared_key, peer_pk.data(), my_sk_) != 0) {
                    wxLogError("Failed to compute shared key");
                    return;
                }

                std::string chat_id = generateUniqueID();
                auto session = std::make_shared<P2PSession>(std::move(socket), this,
                                                             chat_id, shared_key);

                ChatInfo info;
                info.chatID = chat_id;
                info.peerID = peer_id;
                info.localAlias = "";
                std::memcpy(info.shared_key, shared_key, crypto_box_BEFORENMBYTES);
                info.active = true;
                chats_[chat_id] = info;

                p2p_manager_->add_session(chat_id, session);
                session->start();

                RegenerateUserID();
                RegenerateKeypair();

                RefreshChatList();
                wxMessageBox("Encrypted chat started with " + truncateID(peer_id),
                             "Success", wxOK | wxICON_INFORMATION);

                sodium_memzero(shared_key, sizeof(shared_key));
            } catch (const std::exception& e) {
                wxLogError("Error accepting invitation: %s", e.what());
            }
        } else {
            try {
                auto socket = p2p_manager_->take_pending_socket(pending_socket_id);
                std::string reject_msg = "REJECT\n";
                boost::asio::write(socket, boost::asio::buffer(reject_msg));
            } catch (...) {
                
            }
        }
    }
}

void MyFrame::OnPeerConnected(wxCommandEvent& event) {
    wxString data = event.GetString();
    wxArrayString parts = wxSplit(data, ';');

    if (parts.GetCount() >= 3) {
        std::string chat_id = parts[0].ToStdString();
        std::string peer_id = parts[1].ToStdString();
        std::string sk_hex = parts[2].ToStdString();

        auto sk_bytes = hex_to_bytes(sk_hex);

        ChatInfo info;
        info.chatID = chat_id;
        info.peerID = peer_id;
        info.localAlias = "";
        info.active = true;
        if (sk_bytes.size() == crypto_box_BEFORENMBYTES) {
            std::memcpy(info.shared_key, sk_bytes.data(), crypto_box_BEFORENMBYTES);
        }
        chats_[chat_id] = info;

        RegenerateUserID();
        RegenerateKeypair();

        RefreshChatList();
        wxMessageBox("Encrypted connection established with " + truncateID(peer_id),
                     "Success", wxOK | wxICON_INFORMATION);
    }
}

void MyFrame::OnPeerDisconnected(wxCommandEvent& event) {
    std::string* chat_id_ptr = static_cast<std::string*>(event.GetClientData());
    if (!chat_id_ptr) return;

    std::string chat_id = *chat_id_ptr;
    delete chat_id_ptr;

    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        it->second.active = false;
        std::string name = GetChatDisplayName(it->second);

        if (chat_id == active_chat_id_) {
            chat_display_->AppendText("[" + name + " disconnected]\n");
            message_input_->Enable(false);
            send_button_->Enable(false);
        }

        sodium_memzero(it->second.shared_key, sizeof(it->second.shared_key));
        RefreshChatList();
    }
}

void MyFrame::OnClose(wxCloseEvent& event) {
    for (auto& [id, info] : chats_) {
        sodium_memzero(info.shared_key, sizeof(info.shared_key));
    }
    p2p_manager_.reset();
    server_client_.reset();
    event.Skip();
}

void MyFrame::UpdateUI() {
    if (connection_mode_ == ConnectionMode::PEER_TO_PEER) {
        new_chat_button_->Enable(true);
    } else {
        new_chat_button_->Enable(connected_);
    }
}

void MyFrame::RefreshChatList() {
    chat_list_->Clear();
    for (const auto& [chat_id, chat_info] : chats_) {
        if (chat_info.active) {
            chat_list_->Append(GetChatDisplayName(chat_info));
        }
    }
}

void MyFrame::LoadChatMessages(const std::string& chat_id) {
    chat_display_->Clear();
    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        for (const auto& [sender, message] : it->second.messageCache) {
            chat_display_->AppendText(sender + ": " + message + "\n");
        }
    }
}

void MyFrame::RegenerateUserID() {
    current_user_id_ = generateUniqueID();
    user_id_label_->SetLabel("Your ID: " + current_user_id_);
}

void MyFrame::RegenerateKeypair() {
    sodium_memzero(my_sk_, sizeof(my_sk_));
    sodium_memzero(my_pk_, sizeof(my_pk_));
    crypto_box_keypair(my_pk_, my_sk_);
}

std::string MyFrame::GetChatDisplayName(const ChatInfo& info) const {
    if (!info.localAlias.empty()) {
        return info.localAlias;
    }
    return truncateID(info.peerID);
}
