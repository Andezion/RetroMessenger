#include <wx/wx.h>
#include <wx/listbox.h>
#include <boost/array.hpp>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class EchoClient
{
    boost::asio::io_context io;
    tcp::socket socket{io};
public:
    void connect(const std::string & host, const std::string & port)
    {
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, port);
        boost::asio::connect(socket, endpoints);
    }

    void send(const std::string &message)
    {
        boost::asio::write(socket, boost::asio::buffer(message));
    }

    std::string receive()
    {
        boost::array<char, 128> buf;
        boost::system::error_code error;

        size_t len = socket.read_some(boost::asio::buffer(buf), error);
        return std::string(buf.data(), len);
    }

    void run()
    {
        io.run();
    }
};

class MyApp : public wxApp
{
public:
    virtual bool OnInit();
};

class MyFrame : public wxFrame
{
public:
    MyFrame(const wxString& title);

private:
    wxListBox* contactList;
    wxTextCtrl* chatDisplay;
    wxTextCtrl* messageInput;
    wxButton* sendButton;
    EchoClient client;

    void OnSend(wxCommandEvent& event);

    wxDECLARE_EVENT_TABLE();
};

enum
{
    ID_Send = wxID_HIGHEST + 1
};

wxBEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_BUTTON(ID_Send, MyFrame::OnSend)
wxEND_EVENT_TABLE()

wxIMPLEMENT_APP(MyApp);

bool MyApp::OnInit()
{
    MyFrame* frame = new MyFrame("Messenger");
    frame->Show(true);
    return true;
}

MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(600, 400))
{
    auto* mainSizer = new wxBoxSizer(wxHORIZONTAL);

    contactList = new wxListBox(this, wxID_ANY);
    contactList->Append("User1");
    contactList->Append("User2");
    contactList->Append("User3");

    mainSizer->Add(contactList, 1, wxEXPAND | wxALL, 5);

    wxBoxSizer* chatSizer = new wxBoxSizer(wxVERTICAL);

    chatDisplay = new wxTextCtrl(this, wxID_ANY, title,
                                 wxDefaultPosition, wxDefaultSize,
                                 wxTE_MULTILINE | wxTE_READONLY);
    chatSizer->Add(chatDisplay, 1, wxEXPAND | wxALL, 5);

    wxBoxSizer* inputSizer = new wxBoxSizer(wxHORIZONTAL);

    messageInput = new wxTextCtrl(this, wxID_ANY, "",
                                  wxDefaultPosition, wxDefaultSize,
                                  wxTE_PROCESS_ENTER);
    inputSizer->Add(messageInput, 1, wxEXPAND | wxALL, 5);

    sendButton = new wxButton(this, ID_Send, "Send");
    inputSizer->Add(sendButton, 0, wxALL, 5);

    chatSizer->Add(inputSizer, 0, wxEXPAND);

    mainSizer->Add(chatSizer, 3, wxEXPAND);

    SetSizer(mainSizer);
    Centre();
}

void MyFrame::OnSend(wxCommandEvent& event)
{
    wxString message = messageInput->GetValue();
    if (!message.IsEmpty())
    {
        client.send(std::string(message.mb_str()));
        wxString reply = wxString::FromUTF8(client.receive());
        chatDisplay->AppendText("You: " + message + "\n");
        messageInput->Clear();
    }
}

