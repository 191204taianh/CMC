#include <windows.h>

int main(void) {
    /* Note: MessageBox is a macro that resolves to MessageBoxA or MessageBoxW.
       Here we call MessageBoxA explicitly for an ANSI (narrow‐char) build. */
    MessageBoxA(
        NULL, 
        "When life gives you tangerines",   /* lpText */
        "Notice",                            /* lpCaption */
        MB_OK | MB_ICONWARNING               /* uType */
    );
    return 0;
}
