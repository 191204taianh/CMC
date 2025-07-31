#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Convert an RVA to a file offset
DWORD RvaToFileOffset(DWORD rva, IMAGE_SECTION_HEADER *sections, WORD numberOfSections) {
    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD sectVA   = sections[i].VirtualAddress;
        DWORD sectSize = sections[i].Misc.VirtualSize;
        if (rva >= sectVA && rva < sectVA + sectSize) {
            return (rva - sectVA) + sections[i].PointerToRawData;
        }
    }
    return 0;
}

void ListExportedFunctions(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return;
    }

    // ---- Read DOS header ----
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, 1, sizeof(dosHeader), f) != sizeof(dosHeader) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Not a valid PE file\n");
        fclose(f);
        return;
    }

    // ---- Seek to NT headers ----
    if (fseek(f, dosHeader.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "Seek failed\n");
        fclose(f);
        return;
    }

    // ---- Read NT signature ----
    DWORD ntSig;
    fread(&ntSig, 1, sizeof(ntSig), f);
    if (ntSig != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "PE header not found\n");
        fclose(f);
        return;
    }

    // ---- Read FileHeader ----
    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, 1, sizeof(fileHeader), f);

    // ---- Read OptionalHeader (32 vs 64) ----
    DWORD exportRVA = 0, exportSize = 0;
    BOOL is64 = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

    if (is64) {
        IMAGE_OPTIONAL_HEADER64 opt64;
        fread(&opt64, 1, sizeof(opt64), f);
        exportRVA  = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        IMAGE_OPTIONAL_HEADER32 opt32;
        fread(&opt32, 1, sizeof(opt32), f);
        exportRVA  = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (exportRVA == 0) {
        printf("No export table found.\n");
        fclose(f);
        return;
    }

    // ---- Read SectionHeaders ----
    WORD numSecs = fileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *sections =
        malloc(sizeof(IMAGE_SECTION_HEADER) * numSecs);
    fread(sections, sizeof(IMAGE_SECTION_HEADER), numSecs, f);

    // ---- Compute file offset of EXPORT_DIRECTORY ----
    DWORD expOff = RvaToFileOffset(exportRVA, sections, numSecs);
    if (expOff == 0) {
        fprintf(stderr, "Cannot locate export directory\n");
        free(sections);
        fclose(f);
        return;
    }

    // ---- Read EXPORT_DIRECTORY ----
    if (fseek(f, expOff, SEEK_SET) != 0) {
        fprintf(stderr, "Seek to export dir failed\n");
        free(sections);
        fclose(f);
        return;
    }
    IMAGE_EXPORT_DIRECTORY expDir;
    fread(&expDir, 1, sizeof(expDir), f);

    // ---- Read module name ----
    DWORD nameOff = RvaToFileOffset(expDir.Name, sections, numSecs);
    if (fseek(f, nameOff, SEEK_SET) != 0) { /* ignore */ }
    char moduleName[256] = {0};
    fgets(moduleName, sizeof(moduleName), f);

    printf("---- EXPORTED FUNCTIONS ----\n");
    printf("Module Name: %s\n", moduleName);
    printf("Number of Functions: %u\n", expDir.NumberOfFunctions);
    printf("Number of Named Functions: %u\n", expDir.NumberOfNames);

    if (expDir.NumberOfNames > 0) {
        // Read arrays of RVAs and ordinals
        DWORD *nameRVAs = malloc(expDir.NumberOfNames * sizeof(DWORD));
        WORD  *ordinals = malloc(expDir.NumberOfNames * sizeof(WORD));

        DWORD addrNames   = RvaToFileOffset(expDir.AddressOfNames, sections, numSecs);
        DWORD addrOrds    = RvaToFileOffset(expDir.AddressOfNameOrdinals, sections, numSecs);
        DWORD addrFuncs   = RvaToFileOffset(expDir.AddressOfFunctions, sections, numSecs);

        fseek(f, addrNames, SEEK_SET);
        fread(nameRVAs, sizeof(DWORD), expDir.NumberOfNames, f);

        fseek(f, addrOrds, SEEK_SET);
        fread(ordinals, sizeof(WORD), expDir.NumberOfNames, f);

        for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
            DWORD fnNameOff = RvaToFileOffset(nameRVAs[i], sections, numSecs);
            fseek(f, fnNameOff, SEEK_SET);
            char fnName[256] = {0};
            fgets(fnName, sizeof(fnName), f);

            // Read function RVA via ordinals
            fseek(f, addrFuncs + ordinals[i] * sizeof(DWORD), SEEK_SET);
            DWORD fnRVA;
            fread(&fnRVA, sizeof(DWORD), 1, f);

            printf("  - %s (Ordinal: %u, RVA: 0x%X)\n",
                   fnName,
                   expDir.Base + ordinals[i],
                   fnRVA);
        }

        free(nameRVAs);
        free(ordinals);
    }

    printf("-----------------------------\n");
    free(sections);
    fclose(f);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PE file>\n", argv[0]);
        return 1;
    }
    ListExportedFunctions(argv[1]);
    return 0;
}
