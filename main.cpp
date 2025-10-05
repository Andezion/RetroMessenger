#include <wx/wx.h>

class MyApp : public wxApp
{
public:
    virtual bool OnInit();
};

class MyFrame : public wxFrame
{
public:
    MyFrame(const wxString& title);
    void OnQuit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnSize(wxSizeEvent& event);
    void OnButtonOK(wxCommandEvent& event);
private:
    DECLARE_EVENT_TABLE()
};

DECLARE_APP(MyApp)
IMPLEMENT_APP(MyApp)

bool MyApp::OnInit()
{
    MyFrame *frame = new MyFrame(wxT("Minimal wxWidgets App"));
    frame->Show(true);

    return true;
}

BEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_MENU(wxID_ABOUT, MyFrame::OnAbout)
    EVT_MENU(wxID_EXIT, MyFrame::OnQuit)
    EVT_SIZE ( MyFrame::OnSize)
    EVT_BUTTON (wxID_OK, MyFrame::OnButtonOK)
END_EVENT_TABLE()

void MyFrame::OnAbout(wxCommandEvent& event)
{
    wxString msg;
    msg.Printf(wxT("Hello and welcome to %s"),
    wxVERSION_STRING);
    wxMessageBox(msg, wxT("About Minimal"),
    wxOK | wxICON_INFORMATION, this);
}

void MyFrame::OnButtonOK(wxCommandEvent &event)
{
    auto *button = new wxButton(this, wxID_OK, wxT("OK"),
                    wxPoint(200, 200));
}

void MyFrame::OnQuit(wxCommandEvent& event)
{
    Close();
}

MyFrame::MyFrame(const wxString& title)
: wxFrame(NULL, wxID_ANY, title)
{
    wxMenu *fileMenu = new wxMenu;

    wxMenu *helpMenu = new wxMenu;
    helpMenu->Append(wxID_ABOUT, wxT("&About...\tF1"),
    wxT("Show about dialog"));
    fileMenu->Append(wxID_EXIT, wxT("E&xit\tAlt-X"),
    wxT("Quit this program"));
    wxMenuBar *menuBar = new wxMenuBar();
    menuBar->Append(fileMenu, wxT("&File"));
    menuBar->Append(helpMenu, wxT("&Help"));
    SetMenuBar(menuBar);
    CreateStatusBar(2);
    SetStatusText(wxT("Welcome to wxWidgets!"));
}