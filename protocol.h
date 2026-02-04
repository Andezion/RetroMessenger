#pragma once

#include <wx/event.h>
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <mutex>
#include "crypto_utils.h"

using boost::asio::ip::tcp;

// Custom events
wxDECLARE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);
wxDECLARE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);
wxDECLARE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);
wxDECLARE_EVENT(wxEVT_PEER_DISCONNECTED, wxCommandEvent);

// Message framing
std::vector<unsigned char> frame_encode(const std::vector<unsigned char>& payload);
std::vector<unsigned char> frame_encode_string(const std::string& s);

// Data structures for events
struct ReceivedMessageData {
    std::string chat_id;
    std::vector<unsigned char> payload;
};

struct PeerConnectedData {
    std::string chat_id;
    std::string peer_id;
    RatchetState ratchet;
};

// P2P Session class
class P2PSession : public std::enable_shared_from_this<P2PSession> {
public:
    P2PSession(tcp::socket socket, wxEvtHandler* handler, const std::string& chatID);
    
    void start();
    void send_raw(const std::vector<unsigned char>& framed_data);
    std::string get_chat_id() const;

private:
    void read_frame_header();
    void read_frame_payload(uint32_t len);
    void do_write();
    void notify_disconnect();

    tcp::socket socket_;
    wxEvtHandler* event_handler_;
    std::string chat_id_;
    unsigned char header_buf_[4];
    std::vector<unsigned char> payload_buf_;
    std::deque<std::vector<unsigned char>> write_queue_;
};

// P2P Manager class
class P2PManager {
public:
    P2PManager(wxEvtHandler* handler,
               const unsigned char* my_pk, const unsigned char* my_sk,
               unsigned short port = 0);
    ~P2PManager();

    unsigned short get_listening_port() const;
    
    void send_invitation(const std::string& peer_address, const std::string& peer_port,
                         const std::string& my_id);
    
    void send_raw(const std::string& chat_id, const std::vector<unsigned char>& framed_data);
    void add_session(const std::string& chat_id, std::shared_ptr<P2PSession> session);
    void close_chat(const std::string& chat_id);
    
    int store_pending_socket(tcp::socket socket);
    tcp::socket take_pending_socket(int id);

private:
    unsigned short find_available_port();
    void start_accept();
    void handle_new_connection(tcp::socket socket);
    void do_accept();

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
