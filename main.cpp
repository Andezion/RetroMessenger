#include <wx/wx.h>
#include <wx/listbox.h>
#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <boost/asio.hpp>
#include <thread>
#include <memory>
#include <random>
#include <sstream>
#include <iomanip>
#include <map>
#include <deque>


using boost::asio::ip::tcp;

wxDECLARE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_INVITATION_RECEIVED, wxCommandEvent);

wxDECLARE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_PEER_CONNECTED, wxCommandEvent);

std::string generateUniqueID() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << dis(gen);
    return ss.str();
}

enum class ConnectionMode {
    PEER_TO_PEER,
    SERVER
};

struct ChatInfo {
    std::string chatID;
    std::string peerUsername;
    std::string peerID;
    std::vector<std::pair<std::string, std::string>> messageCache; 
    bool active;
};

class P2PSession : public std::enable_shared_from_this<P2PSession> {
public:
    P2PSession(tcp::socket socket, wxEvtHandler* handler, const std::string& chatID)
        : socket_(std::move(socket)), event_handler_(handler), chat_id_(chatID) {}
    
    void start() {
        read_message();
    }
    
    void send_message(const std::string& message) {
        auto self(shared_from_this());
        boost::asio::post(socket_.get_executor(), [this, self, message]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(message + "\n");
            if (!write_in_progress) {
                do_write();
            }
        });
    }
    
    std::string get_chat_id() const { return chat_id_; }

private:
    void read_message() {
        auto self(shared_from_this());
        boost::asio::async_read_until(socket_, buffer_, '\n',
            [this, self](const boost::system::error_code& ec, std::size_t) {
                if (!ec) {
                    std::istream is(&buffer_);
                    std::string message;
                    std::getline(is, message);
                    
                    if (event_handler_) {
                        wxCommandEvent event(wxEVT_MESSAGE_RECEIVED);
                        event.SetString(wxString::FromUTF8(message));
                        event.SetInt(0); 
                        event.SetClientData(new std::string(chat_id_));
                        wxQueueEvent(event_handler_, event.Clone());
                    }
                    
                    read_message();
                } else {
                    wxLogError("Read error: %s", ec.message().c_str());
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
                    wxLogError("Write error: %s", ec.message().c_str());
                }
            });
    }
    
    tcp::socket socket_;
    wxEvtHandler* event_handler_;
    std::string chat_id_;
    boost::asio::streambuf buffer_;
    std::deque<std::string> write_queue_;
};

class P2PManager {
public:
    P2PManager(wxEvtHandler* handler, unsigned short port = 0)
        : event_handler_(handler),
          acceptor_(io_context_),
          listening_port_(port) {
        
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
                        const std::string& username, const std::string& my_id) {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        tcp::resolver resolver(io_context_);
        
        try {
            auto endpoints = resolver.resolve(peer_address, peer_port);
            boost::asio::connect(*socket, endpoints);
            
            std::string invite_msg = "INVITE:" + username + ":" + my_id + "\n";
            boost::asio::write(*socket, boost::asio::buffer(invite_msg));
            
            boost::asio::streambuf buffer;
            boost::asio::read_until(*socket, buffer, '\n');
            std::istream is(&buffer);
            std::string response;
            std::getline(is, response);
            
            if (response.substr(0, 6) == "ACCEPT") {
                size_t pos1 = response.find(':', 7);
                std::string peer_username = response.substr(7, pos1 - 7);
                std::string peer_id = response.substr(pos1 + 1);
                
                std::string chat_id = generateUniqueID();
                auto session = std::make_shared<P2PSession>(std::move(*socket), event_handler_, chat_id);
                sessions_[chat_id] = session;
                session->start();
                
                wxCommandEvent event(wxEVT_PEER_CONNECTED);
                event.SetString(wxString::Format("%s;%s;%s", chat_id, peer_username, peer_id));
                wxQueueEvent(event_handler_, event.Clone());
            }
        } catch (const std::exception& e) {
            wxLogError("Failed to send invitation: %s", e.what());
        }
    }
    
    void send_message(const std::string& chat_id, const std::string& message) {
        auto it = sessions_.find(chat_id);
        if (it != sessions_.end()) {
            it->second->send_message(message);
        }
    }
    
    void close_chat(const std::string& chat_id) {
        sessions_.erase(chat_id);
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
            boost::asio::streambuf buffer;
            boost::asio::read_until(socket, buffer, '\n');
            std::istream is(&buffer);
            std::string invite_msg;
            std::getline(is, invite_msg);
            
            if (invite_msg.substr(0, 6) == "INVITE") {
                size_t pos1 = invite_msg.find(':', 7);
                std::string peer_username = invite_msg.substr(7, pos1 - 7);
                std::string peer_id = invite_msg.substr(pos1 + 1);
                
                auto socket_ptr = new tcp::socket(std::move(socket));
                
                wxCommandEvent event(wxEVT_INVITATION_RECEIVED);
                event.SetString(wxString::Format("%s;%s;%p", peer_username, peer_id, 
                                                static_cast<void*>(socket_ptr)));
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
    std::map<std::string, std::shared_ptr<P2PSession>> sessions_;
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
        : wxDialog(parent, wxID_ANY, "Start New Chat", wxDefaultPosition, wxSize(450, 360)) {
        
        auto* sizer = new wxBoxSizer(wxVERTICAL);
        
        sizer->Add(new wxStaticText(this, wxID_ANY, "Enter peer information to start a chat:"), 0, wxALL, 10);
        
        auto* username_sizer = new wxBoxSizer(wxHORIZONTAL);
        username_sizer->Add(new wxStaticText(this, wxID_ANY, "Username:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
        username_input_ = new wxTextCtrl(this, wxID_ANY);
        username_sizer->Add(username_input_, 1, wxEXPAND);
        sizer->Add(username_sizer, 0, wxEXPAND | wxALL, 10);
        
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
    
    std::string get_username() const { return username_input_->GetValue().ToStdString(); }
    std::string get_address() const { return address_input_->GetValue().ToStdString(); }
    std::string get_port() const { return port_input_->GetValue().ToStdString(); }

private:
    wxTextCtrl* username_input_;
    wxTextCtrl* address_input_;
    wxTextCtrl* port_input_;
};

class MyFrame : public wxFrame {
public:
    MyFrame(const wxString& title);
    ~MyFrame();

private:
    wxStaticText* user_id_label_;
    wxTextCtrl* username_input_;
    wxListBox* chat_list_;
    wxTextCtrl* chat_display_;
    wxTextCtrl* message_input_;
    wxButton* send_button_;
    wxButton* new_chat_button_;
    wxButton* settings_button_;
    wxButton* end_chat_button_;
    
    std::string username_;
    std::string current_user_id_;
    ConnectionMode connection_mode_;
    std::map<std::string, ChatInfo> chats_;
    std::string active_chat_id_;
    
    std::unique_ptr<P2PManager> p2p_manager_;
    std::unique_ptr<ServerClient> server_client_;
    bool connected_;
    
    void OnNewChat(wxCommandEvent& event);
    void OnSend(wxCommandEvent& event);
    void OnSettings(wxCommandEvent& event);
    void OnEndChat(wxCommandEvent& event);
    void OnChatSelected(wxCommandEvent& event);
    void OnUsernameChanged(wxCommandEvent& event);
    void OnMessageReceived(wxCommandEvent& event);
    void OnInvitationReceived(wxCommandEvent& event);
    void OnPeerConnected(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);
    
    void UpdateUI();
    void RefreshChatList();
    void LoadChatMessages(const std::string& chat_id);
    void RegenerateUserID();
    
    wxDECLARE_EVENT_TABLE();
};

enum {
    ID_Send = wxID_HIGHEST + 1,
    ID_NewChat,
    ID_Settings,
    ID_EndChat,
    ID_ChatList,
    ID_Username
};

wxBEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_BUTTON(ID_Send, MyFrame::OnSend)
    EVT_BUTTON(ID_NewChat, MyFrame::OnNewChat)
    EVT_BUTTON(ID_Settings, MyFrame::OnSettings)
    EVT_BUTTON(ID_EndChat, MyFrame::OnEndChat)
    EVT_LISTBOX(ID_ChatList, MyFrame::OnChatSelected)
    EVT_TEXT(ID_Username, MyFrame::OnUsernameChanged)
    EVT_COMMAND(wxID_ANY, wxEVT_MESSAGE_RECEIVED, MyFrame::OnMessageReceived)
    EVT_COMMAND(wxID_ANY, wxEVT_INVITATION_RECEIVED, MyFrame::OnInvitationReceived)
    EVT_COMMAND(wxID_ANY, wxEVT_PEER_CONNECTED, MyFrame::OnPeerConnected)
    EVT_CLOSE(MyFrame::OnClose)
wxEND_EVENT_TABLE()

class MyApp : public wxApp {
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(MyApp);

bool MyApp::OnInit() {
    auto* frame = new MyFrame("RetroMessenger - P2P Mode");
    frame->Show(true);
    return true;
}

MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(900, 600)),
      connection_mode_(ConnectionMode::PEER_TO_PEER),
      connected_(false) {
    
    username_ = "User";
    current_user_id_ = generateUniqueID();
    
    auto* main_sizer = new wxBoxSizer(wxVERTICAL);
    
    auto* top_bar = new wxPanel(this);
    auto* top_sizer = new wxBoxSizer(wxHORIZONTAL);
    
    auto* profile_sizer = new wxBoxSizer(wxVERTICAL);
    auto* username_sizer = new wxBoxSizer(wxHORIZONTAL);
    username_sizer->Add(new wxStaticText(top_bar, wxID_ANY, "Username:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    username_input_ = new wxTextCtrl(top_bar, ID_Username, username_);
    username_sizer->Add(username_input_, 1, wxEXPAND);
    profile_sizer->Add(username_sizer, 0, wxEXPAND | wxALL, 5);
    
    user_id_label_ = new wxStaticText(top_bar, wxID_ANY, "ID: " + current_user_id_);
    profile_sizer->Add(user_id_label_, 0, wxALL, 5);
    top_sizer->Add(profile_sizer, 1, wxEXPAND);
    
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
    
    message_input_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent& e) {
        if (!active_chat_id_.empty()) {
            wxCommandEvent dummy;
            OnSend(dummy);
        }
    });
    
    p2p_manager_ = std::make_unique<P2PManager>(this);
    wxLogMessage("P2P Manager started on port %d", p2p_manager_->get_listening_port());
    
    UpdateUI();
}

MyFrame::~MyFrame() {
    p2p_manager_.reset();
    server_client_.reset();
}

void MyFrame::OnNewChat(wxCommandEvent& event) {
    if (connection_mode_ == ConnectionMode::PEER_TO_PEER) {
        NewChatDialog dialog(this);
        if (dialog.ShowModal() == wxID_OK) {
            std::string peer_username = dialog.get_username();
            std::string peer_address = dialog.get_address();
            std::string peer_port = dialog.get_port();
            
            if (!peer_username.empty()) {
                p2p_manager_->send_invitation(peer_address, peer_port, username_, current_user_id_);
                wxMessageBox("Invitation sent to " + peer_username, "Info", wxOK | wxICON_INFORMATION);
            }
        }
    } else {
        wxMessageBox("Server mode not fully implemented in this version", "Info", wxOK | wxICON_INFORMATION);
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
    chat.messageCache.push_back({username_, msg});
    
    chat_display_->AppendText(username_ + ": " + message + "\n");
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
                    p2p_manager_ = std::make_unique<P2PManager>(this);
                }
                SetTitle("RetroMessenger - P2P Mode");
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
        
        chats_.erase(active_chat_id_);
        active_chat_id_.clear();
        
        RegenerateUserID();
        
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
        wxString chat_name = chat_list_->GetString(selection);
        
        for (const auto& [chat_id, chat_info] : chats_) {
            if (chat_info.peerUsername == chat_name.ToStdString()) {
                active_chat_id_ = chat_id;
                LoadChatMessages(chat_id);
                message_input_->Enable(true);
                send_button_->Enable(true);
                end_chat_button_->Enable(true);
                break;
            }
        }
    }
}

void MyFrame::OnUsernameChanged(wxCommandEvent& event) {
    username_ = username_input_->GetValue().ToStdString();
}

void MyFrame::OnMessageReceived(wxCommandEvent& event) {
    wxString message = event.GetString();
    std::string* chat_id_ptr = static_cast<std::string*>(event.GetClientData());
    
    if (chat_id_ptr) {
        std::string chat_id = *chat_id_ptr;
        delete chat_id_ptr;
        
        auto it = chats_.find(chat_id);
        if (it != chats_.end()) {
            it->second.messageCache.push_back({it->second.peerUsername, message.ToStdString()});
            
            if (chat_id == active_chat_id_) {
                chat_display_->AppendText(it->second.peerUsername + ": " + message + "\n");
            }
        }
    }
}

void MyFrame::OnInvitationReceived(wxCommandEvent& event) {
    wxString data = event.GetString();
    wxArrayString parts = wxSplit(data, ';');
    
    if (parts.GetCount() >= 3) {
        std::string peer_username = parts[0].ToStdString();
        std::string peer_id = parts[1].ToStdString();
        
        // Parse the pointer correctly
        void* ptr = nullptr;
        if (std::sscanf(parts[2].c_str(), "%p", &ptr) != 1 || ptr == nullptr) {
            wxLogError("Invalid socket pointer received");
            return;
        }
        tcp::socket* socket_ptr = static_cast<tcp::socket*>(ptr);
        
        int answer = wxMessageBox(peer_username + " wants to start a chat with you. Accept?",
                                 "Chat Invitation", wxYES_NO | wxICON_QUESTION);
        
        if (answer == wxYES) {
            try {
                std::string accept_msg = "ACCEPT:" + username_ + ":" + current_user_id_ + "\n";
                boost::asio::write(*socket_ptr, boost::asio::buffer(accept_msg));
                
                std::string chat_id = generateUniqueID();
                auto session = std::make_shared<P2PSession>(std::move(*socket_ptr), this, chat_id);
                
                ChatInfo info;
                info.chatID = chat_id;
                info.peerUsername = peer_username;
                info.peerID = peer_id;
                info.active = true;
                chats_[chat_id] = info;
                
                session->start();
                
                RegenerateUserID();
                
                RefreshChatList();
                wxMessageBox("Chat started with " + peer_username, "Success", wxOK | wxICON_INFORMATION);
                
                delete socket_ptr; // Clean up the socket object
            } catch (const std::exception& e) {
                wxLogError("Error accepting invitation: %s", e.what());
                delete socket_ptr;
            }
        } else {
            try {
                std::string reject_msg = "REJECT\n";
                boost::asio::write(*socket_ptr, boost::asio::buffer(reject_msg));
            } catch (...) {
                // Ignore errors on reject
            }
            delete socket_ptr;
        }
    }
}

void MyFrame::OnPeerConnected(wxCommandEvent& event) {
    wxString data = event.GetString();
    wxArrayString parts = wxSplit(data, ';');
    
    if (parts.GetCount() >= 3) {
        std::string chat_id = parts[0].ToStdString();
        std::string peer_username = parts[1].ToStdString();
        std::string peer_id = parts[2].ToStdString();
        
        ChatInfo info;
        info.chatID = chat_id;
        info.peerUsername = peer_username;
        info.peerID = peer_id;
        info.active = true;
        chats_[chat_id] = info;
        
        RegenerateUserID();
        
        RefreshChatList();
        wxMessageBox("Successfully connected to " + peer_username, "Success", wxOK | wxICON_INFORMATION);
    }
}

void MyFrame::OnClose(wxCloseEvent& event) {
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
            chat_list_->Append(chat_info.peerUsername);
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
    user_id_label_->SetLabel("ID: " + current_user_id_);
}