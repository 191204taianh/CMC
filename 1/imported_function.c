#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Convert Relative Virtual Address (RVA) to File Offset
DWORD RvaToFileOffset(DWORD rva,
                      IMAGE_SECTION_HEADER* sections,
                      int numSections)
{
    for (int i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER* sec = &sections[i];
        if (rva >= sec->VirtualAddress &&
            rva <  sec->VirtualAddress + sec->Misc.VirtualSize)
        {
            return (rva - sec->VirtualAddress) + sec->PointerToRawData;
        }
    }
    return 0;
}

void ListImportedFunctions(const char* filename)
{
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return;
    }

    // --- Read DOS header ---
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, f) != 1 ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(stderr, "Invalid PE file format!\n");
        fclose(f);
        return;
    }

    // --- Locate NT headers ---
    fseek(f, dosHeader.e_lfanew, SEEK_SET);
    DWORD ntSig;
    if (fread(&ntSig, sizeof(ntSig), 1, f) != 1 ||
        ntSig != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "PE header not found!\n");
        fclose(f);
        return;
    }

    // --- File header ---
    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof(fileHeader), 1, f);

    // --- Optional header & import directory info ---
    BOOL    is64Bit = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    DWORD   importRVA = 0, importSize = 0;

    if (is64Bit) {
        IMAGE_OPTIONAL_HEADER64 opt64;
        fread(&opt64, sizeof(opt64), 1, f);
        importRVA  = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        IMAGE_OPTIONAL_HEADER32 opt32;
        fread(&opt32, sizeof(opt32), 1, f);
        importRVA  = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importRVA == 0) {
        printf("No Import Table found.\n");
        fclose(f);
        return;
    }

    // --- Read section headers ---
    int numSecs = fileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections =
        malloc(sizeof(IMAGE_SECTION_HEADER) * numSecs);
    for (int i = 0; i < numSecs; i++) {
        fread(&sections[i], sizeof(IMAGE_SECTION_HEADER), 1, f);
    }

    // --- Compute file offset of import directory ---
    DWORD importOffset = RvaToFileOffset(importRVA, sections, numSecs);
    if (importOffset == 0) {
        fprintf(stderr, "Failed to locate import directory in file!\n");
        free(sections);
        fclose(f);
        return;
    }

    printf("---- IMPORTED FUNCTIONS ----\n"
           "File: %s%s\n"
           "-----------------------------\n",
           filename, is64Bit ? " (64-bit)" : " (32-bit)");

    // --- Walk the IMAGE_IMPORT_DESCRIPTOR array ---
    DWORD descOffset = importOffset;
    IMAGE_IMPORT_DESCRIPTOR desc;
    int dllCount = 0, totalFuncs = 0;

    while (1) {
        fseek(f, descOffset, SEEK_SET);
        if (fread(&desc, sizeof(desc), 1, f) != 1 || desc.Name == 0)
            break;

        // Read DLL name
        DWORD nameOffset = RvaToFileOffset(desc.Name, sections, numSecs);
        if (nameOffset == 0) break;
        fseek(f, nameOffset, SEEK_SET);

        char dllName[256];
        int  c, idx = 0;
        while ((c = fgetc(f)) != EOF && c != 0 && idx < 255) {
            dllName[idx++] = (char)c;
        }
        dllName[idx] = '\0';

        printf("DLL #%d: %s\n", ++dllCount, dllName);

        // Choose thunk (OriginalFirstThunk if present, else FirstThunk)
        DWORD thunkRVA = desc.OriginalFirstThunk ? desc.OriginalFirstThunk
                                                 : desc.FirstThunk;
        DWORD thunkOffset = RvaToFileOffset(thunkRVA, sections, numSecs);
        if (thunkOffset == 0) {
            printf("  <cannot locate thunk table>\n");
        } else {
            int funcCount = 0;
            size_t entrySize = is64Bit ? sizeof(ULONGLONG)
                                      : sizeof(DWORD);

            while (1) {
                ULONGLONG raw = 0;
                fseek(f, thunkOffset + funcCount * entrySize, SEEK_SET);

                if (is64Bit) {
                    if (fread(&raw, sizeof(raw), 1, f) != 1) break;
                } else {
                    DWORD raw32;
                    if (fread(&raw32, sizeof(raw32), 1, f) != 1) break;
                    raw = raw32;
                }
                if (raw == 0) break;  // end of list

                funcCount++;
                totalFuncs++;

                // Check if imported by ordinal
                BOOL byOrdinal = is64Bit
                    ? (raw & IMAGE_ORDINAL_FLAG64) != 0
                    : (raw & IMAGE_ORDINAL_FLAG32) != 0;

                if (byOrdinal) {
                    WORD ord = (WORD)(raw & 0xFFFF);
                    printf("  %4d. Ordinal: %u\n", funcCount, ord);
                } else {
                    // Imported by name
                    DWORD hintNameRVA    = (DWORD)raw;
                    DWORD hintNameOffset = RvaToFileOffset(
                        hintNameRVA, sections, numSecs);
                    if (hintNameOffset) {
                        fseek(f, hintNameOffset + 2, SEEK_SET);
                        char funcName[256];
                        idx = 0;
                        while ((c = fgetc(f)) != EOF && c != 0 && idx < 255) {
                            funcName[idx++] = (char)c;
                        }
                        funcName[idx] = '\0';
                        printf("  %4d. %s\n", funcCount, funcName);
                    }
                }
            }
        }

        printf("-----------------------------\n");
        descOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    printf("Summary: %d DLLs, %d imported functions\n"
           "-----------------------------\n",
           dllCount, totalFuncs);

    free(sections);
    fclose(f);
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PE file>\n", argv[0]);
        return 1;
    }
    ListImportedFunctions(argv[1]);
    return 0;
}
