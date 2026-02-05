#include "protocol.h"
#include "gui.h"
#include <wx/log.h>
#include <cstring>

wxDEFINE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_DISCONNECTED, wxCommandEvent);

std::vector<unsigned char> frame_encode(const std::vector<unsigned char>& payload) {
    uint32_t len = static_cast<uint32_t>(payload.size());
    std::vector<unsigned char> frame(4 + payload.size());
    frame[0] = (len >> 24) & 0xFF;
    frame[1] = (len >> 16) & 0xFF;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;
    std::memcpy(frame.data() + 4, payload.data(), payload.size());
    return frame;
}

std::vector<unsigned char> frame_encode_string(const std::string& s) {
    std::vector<unsigned char> payload(s.begin(), s.end());
    return frame_encode(payload);
}

P2PSession::P2PSession(tcp::socket socket, wxEvtHandler* handler, const std::string& chatID)
    : socket_(std::move(socket)), event_handler_(handler), chat_id_(chatID)
{
}

void P2PSession::start() {
    read_frame_header();
}

void P2PSession::send_raw(const std::vector<unsigned char>& framed_data) {
    auto self(shared_from_this());
    boost::asio::post(socket_.get_executor(), [this, self, framed_data]() {
        bool write_in_progress = !write_queue_.empty();
        write_queue_.push_back(framed_data);
        if (!write_in_progress) {
            do_write();
        }
    });
}

std::string P2PSession::get_chat_id() const {
    return chat_id_;
}

void P2PSession::read_frame_header() {
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

void P2PSession::read_frame_payload(uint32_t len) {
    auto self(shared_from_this());
    boost::asio::async_read(socket_, boost::asio::buffer(payload_buf_.data(), len),
        [this, self](const boost::system::error_code& ec, std::size_t) {
            if (!ec) {
                if (event_handler_) {
                    auto* msg_data = new ReceivedMessageData();
                    msg_data->chat_id = chat_id_;
                    msg_data->payload.assign(payload_buf_.begin(), payload_buf_.end());

                    wxCommandEvent event(wxEVT_MESSAGE_RECEIVED);
                    event.SetClientData(msg_data);
                    wxQueueEvent(event_handler_, event.Clone());
                }
                read_frame_header();
            } else {
                notify_disconnect();
            }
        });
}

void P2PSession::do_write() {
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

void P2PSession::notify_disconnect() {
    if (event_handler_) {
        wxCommandEvent event(wxEVT_PEER_DISCONNECTED);
        event.SetClientData(new std::string(chat_id_));
        wxQueueEvent(event_handler_, event.Clone());
    }
}

P2PManager::P2PManager(wxEvtHandler* handler,
                       const unsigned char* my_pk, const unsigned char* my_sk,
                       unsigned short port)
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

P2PManager::~P2PManager() {
    io_context_.stop();
    if (io_thread_.joinable()) {
        io_thread_.join();
    }
}

unsigned short P2PManager::get_listening_port() const {
    return listening_port_;
}

void P2PManager::send_invitation(const std::string& peer_address, const std::string& peer_port,
                                  const std::string& my_id, EncryptionMode mode) {
    auto socket_ptr = std::make_shared<tcp::socket>(io_context_);
    auto resolver_ptr = std::make_shared<tcp::resolver>(io_context_);
    
    wxLogMessage("[CONNECT] Starting async connection to %s:%s", peer_address, peer_port);

    resolver_ptr->async_resolve(peer_address, peer_port,
        [this, socket_ptr, resolver_ptr, my_id, mode, peer_address, peer_port]
        (const boost::system::error_code& ec, tcp::resolver::results_type endpoints) {
            if (ec) {
                wxLogError("[CONNECT] Failed to resolve %s:%s - %s", 
                          peer_address, peer_port, ec.message());
                
                wxCommandEvent* evt = new wxCommandEvent(wxEVT_COMMAND_BUTTON_CLICKED);
                evt->SetString("Connection failed: " + ec.message());
                wxQueueEvent(event_handler_, evt);
                return;
            }

            wxLogMessage("[CONNECT] Resolved address, connecting...");

            boost::asio::async_connect(*socket_ptr, endpoints,
                [this, socket_ptr, my_id, mode, peer_address, peer_port]
                (const boost::system::error_code& ec, const tcp::endpoint&) {
                    if (ec) {
                        wxLogError("[CONNECT] Failed to connect to %s:%s - %s",
                                  peer_address, peer_port, ec.message());
                        
                        wxCommandEvent* evt = new wxCommandEvent(wxEVT_COMMAND_BUTTON_CLICKED);
                        evt->SetString("Connection failed: " + ec.message());
                        wxQueueEvent(event_handler_, evt);
                        return;
                    }

                    wxLogMessage("[CONNECT] TCP connected, sending invitation...");

                    std::string pk_hex = bytes_to_hex(my_pk_, crypto_box_PUBLICKEYBYTES);
                    std::string invite_msg = "INVITE:" + pk_hex + ":" + my_id + ":" + 
                                            std::to_string(static_cast<int>(mode)) + "\n";

                    auto invite_buffer = std::make_shared<std::string>(invite_msg);
                    boost::asio::async_write(*socket_ptr, boost::asio::buffer(*invite_buffer),
                        [this, socket_ptr, invite_buffer, my_id, mode, peer_address, peer_port]
                        (const boost::system::error_code& ec, std::size_t) {
                            if (ec) {
                                wxLogError("[CONNECT] Failed to send invitation - %s", ec.message());
                                return;
                            }

                            wxLogMessage("[CONNECT] Invitation sent, waiting for response...");

                            auto buffer_ptr = std::make_shared<boost::asio::streambuf>();
                            boost::asio::async_read_until(*socket_ptr, *buffer_ptr, '\n',
                                [this, socket_ptr, buffer_ptr, my_id, mode, peer_address, peer_port]
                                (const boost::system::error_code& ec, std::size_t) {
                                    if (ec) {
                                        wxLogError("[CONNECT] Failed to read response - %s", ec.message());
                                        return;
                                    }

                                    std::istream is(buffer_ptr.get());
                                    std::string response;
                                    std::getline(is, response);

                                    wxLogMessage("[CONNECT] Received response: %s", response);

                                    if (response.substr(0, 6) == "ACCEPT") {
                                        size_t pos1 = response.find(':', 7);
                                        size_t pos2 = response.find(':', pos1 + 1);
                                        
                                        std::string peer_pk_hex = response.substr(7, pos1 - 7);
                                        std::string peer_id = response.substr(pos1 + 1, pos2 - pos1 - 1);
                                        std::string mode_str = response.substr(pos2 + 1);
                                        
                                        EncryptionMode confirmed_mode = static_cast<EncryptionMode>(std::stoi(mode_str));

                                        std::string chat_id = generateUniqueID();

                                        auto* conn_data = new PeerConnectedData();
                                        conn_data->chat_id = chat_id;
                                        conn_data->peer_id = peer_id;
                                        conn_data->encryption_mode = confirmed_mode;

                                        if (confirmed_mode == EncryptionMode::DOUBLE_RATCHET) {
                                            auto peer_pk = hex_to_bytes(peer_pk_hex);
                                            if (peer_pk.size() != crypto_box_PUBLICKEYBYTES) {
                                                wxLogError("[CONNECT] Invalid peer public key size");
                                                return;
                                            }

                                            unsigned char shared_key[crypto_box_BEFORENMBYTES];
                                            if (crypto_box_beforenm(shared_key, peer_pk.data(), my_sk_) != 0) {
                                                wxLogError("[CONNECT] Failed to compute shared key");
                                                return;
                                            }

                                            init_ratchet(conn_data->ratchet, shared_key, true);
                                            sodium_memzero(shared_key, sizeof(shared_key));
                                        }

                                        auto session = std::make_shared<P2PSession>(
                                            std::move(*socket_ptr), event_handler_, chat_id);
                                        
                                        {
                                            std::lock_guard<std::mutex> lock(sessions_mutex_);
                                            sessions_[chat_id] = session;
                                        }
                                        
                                        session->start();

                                        wxCommandEvent event(wxEVT_PEER_CONNECTED);
                                        event.SetClientData(conn_data);
                                        wxQueueEvent(event_handler_, event.Clone());

                                        wxLogMessage("[CONNECT] Connection successful!");
                                    } else if (response.substr(0, 6) == "REJECT") {
                                        wxLogWarning("[CONNECT] Peer rejected the invitation");
                                        
                                        wxCommandEvent* evt = new wxCommandEvent(wxEVT_COMMAND_BUTTON_CLICKED);
                                        evt->SetString("Peer rejected the connection");
                                        wxQueueEvent(event_handler_, evt);
                                    } else {
                                        wxLogError("[CONNECT] Invalid response: %s", response);
                                    }
                                });
                        });
                });
        });
}

void P2PManager::send_raw(const std::string& chat_id, const std::vector<unsigned char>& framed_data) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(chat_id);
    if (it != sessions_.end()) {
        it->second->send_raw(framed_data);
    }
}

void P2PManager::add_session(const std::string& chat_id, std::shared_ptr<P2PSession> session) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_[chat_id] = session;
}

void P2PManager::close_chat(const std::string& chat_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(chat_id);
}

int P2PManager::store_pending_socket(tcp::socket socket) {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    int id = next_pending_id_++;
    pending_sockets_.emplace(id, std::move(socket));
    return id;
}

tcp::socket P2PManager::take_pending_socket(int id) {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto it = pending_sockets_.find(id);
    if (it != pending_sockets_.end()) {
        tcp::socket s = std::move(it->second);
        pending_sockets_.erase(it);
        return s;
    }
    throw std::runtime_error("Pending socket not found");
}

unsigned short P2PManager::find_available_port() {
    tcp::acceptor acc(io_context_, tcp::endpoint(tcp::v4(), 0));
    unsigned short port = acc.local_endpoint().port();
    acc.close();
    return port;
}

void P2PManager::start_accept() {
    auto socket = std::make_shared<tcp::socket>(io_context_);
    acceptor_.async_accept(*socket,
        [this, socket](const boost::system::error_code& ec) {
            if (!ec) {
                handle_new_connection(std::move(*socket));
            }
            do_accept();
        });
}

void P2PManager::handle_new_connection(tcp::socket socket) {
    try {
        wxLogMessage("[SERVER] New incoming connection");

        auto socket_ptr = std::make_shared<tcp::socket>(std::move(socket));
        auto buffer_ptr = std::make_shared<boost::asio::streambuf>();
        
        boost::asio::async_read_until(*socket_ptr, *buffer_ptr, '\n',
            [this, socket_ptr, buffer_ptr](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    wxLogError("[SERVER] Error reading invitation: %s", ec.message());
                    return;
                }

                std::istream is(buffer_ptr.get());
                std::string invite_msg;
                std::getline(is, invite_msg);

                wxLogMessage("[SERVER] Received: %s", invite_msg);

                if (invite_msg.substr(0, 6) == "INVITE") {
                    size_t pos1 = invite_msg.find(':', 7);
                    size_t pos2 = invite_msg.find(':', pos1 + 1);
                    
                    std::string peer_pk_hex = invite_msg.substr(7, pos1 - 7);
                    std::string peer_id = invite_msg.substr(pos1 + 1, pos2 - pos1 - 1);
                    std::string mode_str = invite_msg.substr(pos2 + 1);
                    
                    EncryptionMode mode = static_cast<EncryptionMode>(std::stoi(mode_str));

                    int pending_id = store_pending_socket(std::move(*socket_ptr));

                    wxCommandEvent event(wxEVT_INVITATION_RECEIVED);
                    event.SetString(wxString::Format("%s;%s;%d;%d", 
                        peer_id, peer_pk_hex, pending_id, static_cast<int>(mode)));
                    wxQueueEvent(event_handler_, event.Clone());
                    
                    wxLogMessage("[SERVER] Invitation queued for user approval");
                }
            });
    } catch (const std::exception& e) {
        wxLogError("[SERVER] Error handling connection: %s", e.what());
    }
}

void P2PManager::do_accept() {
    auto socket = std::make_shared<tcp::socket>(io_context_);
    acceptor_.async_accept(*socket,
        [this, socket](const boost::system::error_code& ec) {
            if (!ec) {
                handle_new_connection(std::move(*socket));
            }
            do_accept();
        });
}
