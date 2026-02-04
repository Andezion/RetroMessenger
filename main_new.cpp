#include <wx/wx.h>
#include <sodium.h>
#include "gui.h"

class MyApp : public wxApp {
public:
    virtual bool OnInit() override;
};

wxIMPLEMENT_APP(MyApp);

bool MyApp::OnInit() {
    if (sodium_init() < 0) {
        wxMessageBox("Failed to initialize libsodium!", "Fatal Error", wxOK | wxICON_ERROR);
        return false;
    }
    
    auto* frame = new MyFrame("RetroMessenger - P2P Encrypted (Double Ratchet)");
    frame->Show(true);
    return true;
}
