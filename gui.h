#pragma once

#include <wx/wx.h>
#include <wx/listbox.h>
#include <map>
#include <vector>
#include <string>
#include <memory>
#include "crypto_utils.h"
#include "protocol.h"

enum class EncryptionMode {
    SIMPLE_P2P,      
    DOUBLE_RATCHET  
};

struct ChatInfo {
    std::string chatID;
    std::string peerID;
    std::string localAlias;
    std::vector<std::pair<std::string, std::string>> messageCache;
    RatchetState ratchet;
    bool active;
    bool is_initiator;
    EncryptionMode encryption_mode;
};

class SettingsDialog : public wxDialog {
public:
    SettingsDialog(wxWindow* parent, EncryptionMode current_mode);
    
    EncryptionMode get_encryption_mode() const;

private:
    wxChoice* encryption_choice_;
};

class NewChatDialog : public wxDialog {
public:
    NewChatDialog(wxWindow* parent);
    
    std::string get_address() const;
    std::string get_port() const;

private:
    wxTextCtrl* address_input_;
    wxTextCtrl* port_input_;
};

class AliasDialog : public wxDialog {
public:
    AliasDialog(wxWindow* parent, const std::string& peer_id);
    
    std::string get_alias() const;

private:
    wxTextCtrl* alias_input_;
};

class MyFrame : public wxFrame {
public:
    MyFrame(const wxString& title);
    ~MyFrame();
    wxButton* settings_button_;

private:
    wxStaticText* user_id_label_;
    wxStaticText* port_label_;
    wxListBox* chat_list_;
    wxTextCtrl* chat_display_;
    wxTextCtrl* message_input_;
    wxButton* send_button_;
    wxButton* new_chat_button_;
    wxButton* end_chat_button_;

    std::string current_user_id_;
    std::map<std::string, ChatIn
    EncryptionMode current_encryption_mode_;fo> chats_;
    std::string active_chat_id_;

    unsigned char my_pk_[crypto_box_PUBLICKEYBYTES];
    unsigned char my_sk_[crypto_box_SECRETKEYBYTES];

    std::unique_ptr<P2PManager> p2p_manager_;
ttings(wxCommandEvent& event);
    void OnSe
    void OnNewChat(wxCommandEvent& event);
    void OnSend(wxCommandEvent& event);
    void OnEndChat(wxCommandEvent& event);
    void OnChatSelected(wxCommandEvent& event);
    void OnMessageReceived(wxCommandEvent& event);
    void OnInvitationReceived(wxCommandEvent& event);
    void OnPeerConnected(wxCommandEvent& event);
    void OnPeerDisconnected(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);
    void OnChatListDClick(wxCommandEvent& event);

    void RefreshChatList();
    void LoadChatMessages(const std::string& chat_id);
    void RegenerateUserID();
    void RegenerateKeypair();
    std::string GetChatDisplayName(const ChatInfo& info) const;

    wxDECLARE_EVENT_TABLE();
};

enum {Settings,
    ID_
    ID_Send = wxID_HIGHEST + 1,
    ID_NewChat,
    ID_EndChat,
    ID_ChatList
};
