#include "gui.h"
#include <wx/msgdlg.h>
#include <wx/log.h>
#include <sodium.h>

SettingsDialog::SettingsDialog(wxWindow* parent, EncryptionMode current_mode)
    : wxDialog(parent, wxID_ANY, "Settings", wxDefaultPosition, wxSize(400, 200)) {

    auto* sizer = new wxBoxSizer(wxVERTICAL);

    sizer->Add(new wxStaticText(this, wxID_ANY, "Choose encryption protocol:"), 0, wxALL, 10);

    wxArrayString choices;
    choices.Add("Simple P2P (No Encryption)");
    choices.Add("Double Ratchet (Encrypted)");

    encryption_choice_ = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, choices);
    encryption_choice_->SetSelection(static_cast<int>(current_mode));
    sizer->Add(encryption_choice_, 0, wxEXPAND | wxALL, 10);

    auto* button_sizer = new wxBoxSizer(wxHORIZONTAL);
    button_sizer->Add(new wxButton(this, wxID_OK, "OK"), 0, wxALL, 5);
    button_sizer->Add(new wxButton(this, wxID_CANCEL, "Cancel"), 0, wxALL, 5);
    sizer->Add(button_sizer, 0, wxALIGN_CENTER | wxALL, 10);

    SetSizer(sizer);
    Centre();
}

EncryptionMode SettingsDialog::get_encryption_mode() const {
    return static_cast<EncryptionMode>(encryption_choice_->GetSelection());
}

NewChatDialog::NewChatDialog(wxWindow* parent)
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

std::string NewChatDialog::get_address() const {
    return address_input_->GetValue().ToStdString();
}

std::string NewChatDialog::get_port() const {
    return port_input_->GetValue().ToStdString();
}

AliasDialog::AliasDialog(wxWindow* parent, const std::string& peer_id)
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

std::string AliasDialog::get_alias() const {
    return alias_input_->GetValue().ToStdString();
}

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

MyFrame::MyFrame(const wxString& title),
      current_encryption_mode_(EncryptionMode::DOUBLE_RATCHET) {

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
    top_sizer->Add(settings_button_, 0, wxALL, 5 5);
    top_sizer->Add(info_sizer, 1, wxEXPAND);

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
}

MyFrame::~MyFrame() {
    p2p_manager_.reset();
    sodium_memzero(my_sk_, sizeof(my_sk_));
    sodium_memzero(my_pk_, sizeof(my_pk_));
}

void MyFrame::OnNewChat(wxCommandEvent& event) {
    NewChatDialog dialog(this);
    if (dialog.ShowModal() == wxID_OK) {
        std::string peer_address = dialog.get_address();
        std::string peer_port = dialog.get_port();

        if (!peer_address.empty() && !peer_port.empty()) {
            wxLogMessage("Attempting to connect to %s:%s...", peer_address, peer_port);
            p2p_manager_->send_invitation(peer_address, peer_port, current_user_id_, current_encryption_mode_);
        }
    }
}

void MyFrame::OnSettings(wxCommandEvent& event) {
    SettingsDialog dialog(this, current_encryption_mode_);
    if (dialog.ShowModal() == wxID_OK) {
        current_encryption_mode_ = dialog.get_encryption_mode();
        
        std::string mode_str = (current_encryption_mode_ == EncryptionMode::SIMPLE_P2P) 
                              ? "Simple P2P" : "Double Ratchet";
        wxMessageBox("Encryption mode set to: " + mode_str, "Settings", wxOK | wxICON_INFORMATION);
        wxLogMessage("Encryption mode changed to: %s", mode_str);
    }
}

void MyFrame::OnSend(wxCommandEvent& event) {
    wxString message = message_input_->GetValue();
    if (message.IsEmpty() || active_chat_id_.empty()) {
        return;
    }

    std::string msg = message.ToStdString();
    auto& chat = chats_[active_chat_id_];

    std::vector<unsigned char> framed;
    
    if (chat.encryption_mode == EncryptionMode::DOUBLE_RATCHET) {
        auto encrypted = seal_message_ratchet(msg, chat.ratchet);
        framed = frame_encode(encrypted);
    } else {
        framed = frame_encode_string(msg);
    }
    
    p2p_manager_->send_raw(active_chat_id_, framed);

    chat.messageCache.push_back({truncateID(current_user_id_), msg});
    chat_display_->AppendText(truncateID(current_user_id_) + ": " + message + "\n");
    message_input_->Clear();
}

void MyFrame::OnEndChat(wxCommandEvent& event) {
    if (active_chat_id_.empty()) {
        return;
    }

    int answer = wxMessageBox("Are you sure you want to end this chat? Message history will be deleted.",
                             "Confirm", wxYES_NO | wxICON_QUESTION);

    if (answer == wxYES) {
        p2p_manager_->close_chat(active_chat_id_);

        auto it = chats_.find(active_chat_id_);
        if (it != chats_.end()) {
            it->second.ratchet.zero();
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
    auto* msg_data = static_cast<ReceivedMessageData*>(event.GetClientData());
    if (!msg_data) return;

    std::string chat_id = msg_data->chat_id;
    auto it = chats_.find(chat_id);
    if (it != chats_.end()) {
        std::string message;
        
        if (it->second.encryption_mode == EncryptionMode::DOUBLE_RATCHET) {
            message = unseal_message_ratchet(
                msg_data->payload.data(), msg_data->payload.size(),
                it->second.ratchet);
        } else {
            message = std::string(msg_data->payload.begin(), msg_data->payload.end());
        }

        std::string sender_display = truncateID(it->second.peerID);
        it->second.messageCache.push_back({sender_display, message});

        if (chat_id == active_chat_id_) {
            chat_display_->AppendText(sender_display + ": " + message + "\n");
        }
    }
    delete msg_data;
}

void MyFrame::OnInvitationReceived(wxCommandEvent& event) {
    wxString data = event.GetString();
    wxArrayString parts = wxSplit(data, ';');

    if (parts.GetCount() >= 4) {
        std::string peer_id = parts[0].ToStdString();
        std::string peer_pk_hex = parts[1].ToStdString();
        int pending_socket_id = 0;
        parts[2].ToLong(reinterpret_cast<long*>(&pending_socket_id));
        EncryptionMode mode = static_cast<EncryptionMode>(wxAtoi(parts[3]));

        std::string mode_str = (mode == EncryptionMode::SIMPLE_P2P) 
                              ? "Simple P2P" : "Double Ratchet Encrypted";

        wxLogMessage("Invitation received from %s (mode: %s)", truncateID(peer_id), mode_str);

        int answer = wxMessageBox(
            "Peer " + truncateID(peer_id) + " wants to start a chat (" + mode_str + "). Accept?",
            "Chat Invitation", wxYES_NO | wxICON_QUESTION);

        if (answer == wxYES) {
            try {
                auto socket = p2p_manager_->take_pending_socket(pending_socket_id);

                std::string pk_hex = bytes_to_hex(my_pk_, crypto_box_PUBLICKEYBYTES);
                std::string accept_msg = "ACCEPT:" + pk_hex + ":" + current_user_id_ + ":" + std::to_string(static_cast<int>(mode)) + "\n";
                boost::asio::write(socket, boost::asio::buffer(accept_msg));

                std::string chat_id = generateUniqueID();
                auto session = std::make_shared<P2PSession>(std::move(socket), this, chat_id);

                ChatInfo info;
                info.chatID = chat_id;
                info.peerID = peer_id;
                info.localAlias = "";
                info.active = true;
                info.is_initiator = false;
                info.encryption_mode = mode;

                if (mode == EncryptionMode::DOUBLE_RATCHET) {
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

                    init_ratchet(info.ratchet, shared_key, false);
                    sodium_memzero(shared_key, sizeof(shared_key));
                }

                chats_[chat_id] = info;

                p2p_manager_->add_session(chat_id, session);
                session->start();

                RegenerateUserID();
                if (mode == EncryptionMode::DOUBLE_RATCHET) {
                    RegenerateKeypair();
                }

                RefreshChatList();
                wxLogMessage("Chat started with %s", truncateID(peer_id));
                wxMessageBox("Chat started with " + truncateID(peer_id),
                             "Success", wxOK | wxICON_INFORMATION);

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
    auto* conn_data = static_cast<PeerConnectedData*>(event.GetClientData());
    if (!conn_data) return;

    ChatInfo info;
    info.chatID = conn_data->chat_id;
    info.peerID = conn_data->peer_id;
    info.localAlias = "";
    info.active = true;
    info.is_initiator = true;
    info.encryption_mode = conn_data->encryption_mode;
    
    if (info.encryption_mode == EncryptionMode::DOUBLE_RATCHET) {
        info.ratchet = conn_data->ratchet;
    }

    chats_[conn_data->chat_id] = info;

    RegenerateUserID();
    if (info.encryption_mode == EncryptionMode::DOUBLE_RATCHET) {
        RegenerateKeypair();
    }

    RefreshChatList();
    wxLogMessage("Connection established with %s", truncateID(conn_data->peer_id));
    wxMessageBox("Connection established with " + truncateID(conn_data->peer_id),
                 "Success", wxOK | wxICON_INFORMATION);

    delete conn_data;
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

        it->second.ratchet.zero();
        RefreshChatList();
    }
}

void MyFrame::OnClose(wxCloseEvent& event) {
    for (auto& [id, info] : chats_) {
        info.ratchet.zero();
    }
    p2p_manager_.reset();
    event.Skip();
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
