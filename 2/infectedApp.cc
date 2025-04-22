#include <windows.h>
#include <shellapi.h>
#include <iostream>

int main() {
    // Show the MessageBox first
    MessageBox(0, "You have been infected!", "Alert", MB_OK | MB_ICONWARNING);

    // After user clicks OK, launch the original .exe (anotherApp.exe)
    // Modify the path to the original .exe accordingly
    const char* appPath = "C:\\Users\\ntanh\\OneDrive\\Documents\\CMC\\2\\tsetup-x64.5.12.3.exe"; 
    ShellExecute(0, "open", appPath, 0, 0, SW_SHOWNORMAL);

    return 0;
}
