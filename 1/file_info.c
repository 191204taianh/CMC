#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PRINT_FIELD(name, val) \
    printf("%-30s | %12llu | 0x%llx\n", \
           (name), (unsigned long long)(val), (unsigned long long)(val))

void PrintPEInfo(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file '%s'\n", filename);
        return;
    }

    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, f) != 1) {
        fprintf(stderr, "Failed to read DOS header\n");
        fclose(f);
        return;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Not a valid PE file (MZ signature missing)\n");
        fclose(f);
        return;
    }

    if (fseek(f, dosHeader.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "fseek to NT headers failed\n");
        fclose(f);
        return;
    }

    IMAGE_NT_HEADERS32 ntHeaders;
    if (fread(&ntHeaders, sizeof(ntHeaders), 1, f) != 1) {
        fprintf(stderr, "Failed to read NT headers\n");
        fclose(f);
        return;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "PE signature missing\n");
        fclose(f);
        return;
    }

    printf("---- PE FILE INFO ----\n");
    PRINT_FIELD("Signature",         ntHeaders.Signature);
    PRINT_FIELD("Machine",           ntHeaders.FileHeader.Machine);
    PRINT_FIELD("Number of Symbols", ntHeaders.FileHeader.NumberOfSymbols);
    PRINT_FIELD("Time Date Stamp",   ntHeaders.FileHeader.TimeDateStamp);
    PRINT_FIELD("Size of Opt Header",ntHeaders.FileHeader.SizeOfOptionalHeader);
    PRINT_FIELD("Characteristics",   ntHeaders.FileHeader.Characteristics);
    PRINT_FIELD("Magic",             ntHeaders.OptionalHeader.Magic);

    if (ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        printf(" --> Magic: PE32 (32‐bit)\n\n");
    else if (ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        printf(" --> Magic: PE32+ (64‐bit)\n\n");
    else
        printf(" --> Magic: Unknown (0x%x)\n\n", ntHeaders.OptionalHeader.Magic);

    PRINT_FIELD("DOS Magic",                dosHeader.e_magic);
    PRINT_FIELD("Major Linker Version",     ntHeaders.OptionalHeader.MajorLinkerVersion);
    PRINT_FIELD("Minor Linker Version",     ntHeaders.OptionalHeader.MinorLinkerVersion);
    PRINT_FIELD("Size of Code",             ntHeaders.OptionalHeader.SizeOfCode);
    PRINT_FIELD("Size of Init Data",        ntHeaders.OptionalHeader.SizeOfInitializedData);
    PRINT_FIELD("Number of Sections",       ntHeaders.FileHeader.NumberOfSections);
    PRINT_FIELD("Entry Point RVA",          ntHeaders.OptionalHeader.AddressOfEntryPoint);
    PRINT_FIELD("Image Base",               ntHeaders.OptionalHeader.ImageBase);
    PRINT_FIELD("File Alignment",           ntHeaders.OptionalHeader.FileAlignment);
    PRINT_FIELD("Section Alignment",        ntHeaders.OptionalHeader.SectionAlignment);
    PRINT_FIELD("Size of Image",            ntHeaders.OptionalHeader.SizeOfImage);
    PRINT_FIELD("Import Directory RVA",     ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    PRINT_FIELD("Export Directory RVA",     ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    printf("\n---- SECTION HEADERS ----\n");

    /* Seek to first section header */
    fseek(f, dosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
                + ntHeaders.FileHeader.SizeOfOptionalHeader, SEEK_SET);

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sh;
        if (fread(&sh, sizeof(sh), 1, f) != 1) {
            fprintf(stderr, "Failed to read section header %d\n", i);
            break;
        }

        /* Copy name safely (up to 8 chars + null) */
        char name[9] = {0};
        memcpy(name, sh.Name, 8);

        printf("Section Name:      %s\n", name);
        printf("  Virtual Size:    0x%08x\n", sh.Misc.VirtualSize);
        printf("  Virtual Address: 0x%08x\n", sh.VirtualAddress);
        printf("  Raw Size:        0x%08x\n", sh.SizeOfRawData);
        printf("  Raw Address:     0x%08x\n", sh.PointerToRawData);
        printf("  Characteristics: 0x%08x\n", sh.Characteristics);
        printf("-------------------------------\n");
    }

    fclose(f);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <PE file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    PrintPEInfo(argv[1]);
    return EXIT_SUCCESS;
}
