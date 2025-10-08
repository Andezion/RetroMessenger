#include <wx/wx.h>
#include <wx/listbox.h>
#include <boost/asio.hpp>
#include <thread>
#include <memory>

using boost::asio::ip::tcp;

wxDECLARE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);
wxDEFINE_EVENT(wxEVT_MESSAGE_RECEIVED, wxCommandEvent);

class EchoClient
{
    boost::asio::io_context io;
    tcp::socket socket;
    std::thread io_thread;
    wxEvtHandler* event_handler;
    bool running;

public:
    EchoClient() : socket(io), event_handler(nullptr), running(false) {}

    ~EchoClient() {
        disconnect();
    }

    bool connect(const std::string& host, const std::string& port, wxEvtHandler* handler)
    {
        try
        {
            event_handler = handler;
            tcp::resolver resolver(io);

            const auto endpoints = resolver.resolve(host, port);
            boost::asio::connect(socket, endpoints);

            running = true;
            io_thread = std::thread([this]
            {
                this->read_loop();
            });

            return true;
        }
        catch (const std::exception& e)
        {
            wxLogError("Connection error: %s", e.what());
            return false;
        }
    }

    void send(const std::string& message)
    {
        try
        {
            std::string msg = message + "\n";
            boost::asio::write(socket, boost::asio::buffer(msg));
        }
        catch (const std::exception& e)
        {
            wxLogError("Send error: %s", e.what());
        }
    }

    void disconnect()
    {
        running = false;
        if (socket.is_open())
        {
            socket.close();
        }
        if (io_thread.joinable())
        {
            io_thread.join();
        }
    }

private:
    void read_loop()
    {
        try
        {
            boost::asio::streambuf buffer;
            while (running && socket.is_open())
            {
                boost::system::error_code error;

                boost::asio::read_until(socket, buffer, '\n', error);

                if (error == boost::asio::error::eof)
                {
                    break;
                }
                if (error)
                {
                    throw boost::system::system_error(error);
                }

                std::istream is(&buffer);
                std::string message;
                std::getline(is, message);

                if (event_handler)
                {
                    wxCommandEvent event(wxEVT_MESSAGE_RECEIVED);
                    event.SetString(wxString::FromUTF8(message));
                    wxQueueEvent(event_handler, event.Clone());
                }
            }
        }
        catch (const std::exception& e)
        {
            if (running)
            {
                wxLogError("Read error: %s", e.what());
            }
        }
    }
};

class MyFrame final : public wxFrame
{
public:
    explicit MyFrame(const wxString& title);
    ~MyFrame() override;

private:
    wxListBox* contactList;
    wxTextCtrl* chatDisplay;
    wxTextCtrl* messageInput;
    wxButton* sendButton;
    wxButton* connectButton;
    wxTextCtrl* hostInput;
    wxTextCtrl* portInput;

    std::unique_ptr<EchoClient> client;
    bool connected;

    void OnSend(wxCommandEvent& event);
    void OnConnect(wxCommandEvent& event);
    void OnMessageReceived(wxCommandEvent& event);
    void OnClose(wxCloseEvent& event);

    wxDECLARE_EVENT_TABLE();
};

enum
{
    ID_Send = wxID_HIGHEST + 1,
    ID_Connect
};

wxBEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_BUTTON(ID_Send, MyFrame::OnSend)
    EVT_BUTTON(ID_Connect, MyFrame::OnConnect)
    EVT_COMMAND(wxID_ANY, wxEVT_MESSAGE_RECEIVED, MyFrame::OnMessageReceived)
    EVT_CLOSE(MyFrame::OnClose)
wxEND_EVENT_TABLE()

class MyApp final : public wxApp
{
public:
    bool OnInit() override;
};

wxIMPLEMENT_APP(MyApp);

bool MyApp::OnInit()
{
    auto* frame = new MyFrame("Messenger");
    frame->Show(true);
    return true;
}

MyFrame::MyFrame(const wxString& title)
    : wxFrame(nullptr, wxID_ANY, title, wxDefaultPosition, wxSize(700, 500)),
      connected(false)
{
    auto* mainSizer = new wxBoxSizer(wxVERTICAL);
    auto* connectionSizer = new wxBoxSizer(wxHORIZONTAL);

    connectionSizer->Add(new wxStaticText(this, wxID_ANY, "Host:"), 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    hostInput = new wxTextCtrl(this, wxID_ANY, "127.0.0.1", wxDefaultPosition, wxSize(100, -1));
    connectionSizer->Add(hostInput, 0, wxALL, 5);

    connectionSizer->Add(new wxStaticText(this, wxID_ANY, "Port:"), 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    portInput = new wxTextCtrl(this, wxID_ANY, "12345", wxDefaultPosition, wxSize(60, -1));
    connectionSizer->Add(portInput, 0, wxALL, 5);

    connectButton = new wxButton(this, ID_Connect, "Connect");
    connectionSizer->Add(connectButton, 0, wxALL, 5);

    mainSizer->Add(connectionSizer, 0, wxEXPAND);

    auto* contentSizer = new wxBoxSizer(wxHORIZONTAL);

    contactList = new wxListBox(this, wxID_ANY);
    contactList->Append("All users");
    contentSizer->Add(contactList, 1, wxEXPAND | wxALL, 5);

    auto* chatSizer = new wxBoxSizer(wxVERTICAL);

    chatDisplay = new wxTextCtrl(this, wxID_ANY, "",
                                 wxDefaultPosition, wxDefaultSize,
                                 wxTE_MULTILINE | wxTE_READONLY | wxTE_RICH);
    chatSizer->Add(chatDisplay, 1, wxEXPAND | wxALL, 5);

    auto* inputSizer = new wxBoxSizer(wxHORIZONTAL);
    messageInput = new wxTextCtrl(this, wxID_ANY, "",
                                  wxDefaultPosition, wxDefaultSize,
                                  wxTE_PROCESS_ENTER);
    messageInput->Enable(false);
    inputSizer->Add(messageInput, 1, wxEXPAND | wxALL, 5);

    sendButton = new wxButton(this, ID_Send, "Send");
    sendButton->Enable(false);
    inputSizer->Add(sendButton, 0, wxALL, 5);

    chatSizer->Add(inputSizer, 0, wxEXPAND);
    contentSizer->Add(chatSizer, 3, wxEXPAND);

    mainSizer->Add(contentSizer, 1, wxEXPAND);

    SetSizer(mainSizer);
    Centre();

    messageInput->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent& e) {
        if (connected)
        {
            wxCommandEvent dummy;
            OnSend(dummy);
        }
    });
}

MyFrame::~MyFrame()
{
    if (client)
    {
        client->disconnect();
    }
}

void MyFrame::OnConnect(wxCommandEvent& event)
{
    if (!connected)
    {
        const auto host = std::string(hostInput->GetValue().mb_str());
        const auto port = std::string(portInput->GetValue().mb_str());

        client = std::make_unique<EchoClient>();
        if (client->connect(host, port, this))
        {
            connected = true;
            connectButton->SetLabel("Disconnect");
            messageInput->Enable(true);
            sendButton->Enable(true);
            hostInput->Enable(false);
            portInput->Enable(false);
            chatDisplay->AppendText("=== Connected to server ===\n");
        }
        else
        {
            client.reset();
            wxMessageBox("Failed to connect to server", "Error", wxOK | wxICON_ERROR);
        }
    }
    else
    {
        client->disconnect();
        client.reset();
        connected = false;
        connectButton->SetLabel("Connect");
        messageInput->Enable(false);
        sendButton->Enable(false);
        hostInput->Enable(true);
        portInput->Enable(true);
        chatDisplay->AppendText("=== Disconnected ===\n");
    }
}

void MyFrame::OnSend(wxCommandEvent& event)
{
    if (const wxString message = messageInput->GetValue(); !message.IsEmpty() && connected && client)
    {
        const auto msg = std::string(message.mb_str());
        client->send(msg);

        chatDisplay->AppendText("You: " + message + "\n");
        messageInput->Clear();
    }
}

void MyFrame::OnMessageReceived(wxCommandEvent& event)
{
    const wxString message = event.GetString();
    chatDisplay->AppendText("Server: " + message + "\n");
}

void MyFrame::OnClose(wxCloseEvent& event)
{
    if (client)
    {
        client->disconnect();
    }
    event.Skip();
}