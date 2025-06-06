#include <windows.h>

int main(void) {

    MessageBoxA(
        NULL, 
        "When life gives you tangerines",   
        "Notice",                           
        MB_OK | MB_ICONWARNING              
    );
    return 0;
}
