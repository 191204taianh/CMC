#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

// Convert Relative Virtual Address (RVA) to File Offset
DWORD RvaToFileOffset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections) {
    for (const auto& section : sections) {
        if (rva >= section.VirtualAddress &&
            rva < section.VirtualAddress + section.Misc.VirtualSize)
        {
            return (rva - section.VirtualAddress) + section.PointerToRawData;
        }
    }
    return 0;
}

void ListImportedFunctions(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        return;
    }

    // --- Read DOS header ---
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid PE file format!" << std::endl;
        return;
    }

    // --- Locate NT headers ---
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    DWORD ntSignature;
    file.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
    if (ntSignature != IMAGE_NT_SIGNATURE) {
        std::cerr << "PE header not found!" << std::endl;
        return;
    }

    // --- File header ---
    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // --- Optional header & data directory ---
    bool is64Bit = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    DWORD importDirectoryRVA = 0;
    DWORD importDirectorySize = 0;

    if (is64Bit) {
        IMAGE_OPTIONAL_HEADER64 opt64;
        file.read(reinterpret_cast<char*>(&opt64), sizeof(opt64));
        importDirectoryRVA  = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importDirectorySize = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        IMAGE_OPTIONAL_HEADER32 opt32;
        file.read(reinterpret_cast<char*>(&opt32), sizeof(opt32));
        importDirectoryRVA  = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importDirectorySize = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importDirectoryRVA == 0) {
        std::cout << "No Import Table found.\n";
        return;
    }

    // --- Section headers ---
    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        file.read(reinterpret_cast<char*>(&sections[i]), sizeof(IMAGE_SECTION_HEADER));
    }

    // --- Compute file offset of import directory ---
    DWORD importDirOffset = RvaToFileOffset(importDirectoryRVA, sections);
    if (importDirOffset == 0) {
        std::cerr << "Failed to locate import directory in file!\n";
        return;
    }

    std::cout << "---- IMPORTED FUNCTIONS ----\n"
              << "File: " << filename
              << (is64Bit ? " (64-bit)" : " (32-bit)") << "\n"
              << "-----------------------------\n";

    // --- Walk each IMAGE_IMPORT_DESCRIPTOR by explicit offset ---
    DWORD descOffset = importDirOffset;
    IMAGE_IMPORT_DESCRIPTOR importDesc;
    int dllCount = 0;
    int totalFunctions = 0;

    while (true) {
        // 1) Read next descriptor
        file.seekg(descOffset, std::ios::beg);
        file.read(reinterpret_cast<char*>(&importDesc), sizeof(importDesc));
        if (!file || importDesc.Name == 0) break;  // end of table

        // 2) Read DLL name
        DWORD nameOffset = RvaToFileOffset(importDesc.Name, sections);
        if (nameOffset == 0) break;
        file.seekg(nameOffset, std::ios::beg);
        std::string dllName;
        std::getline(file, dllName, '\0');

        ++dllCount;
        std::cout << "DLL #" << dllCount << ": " << dllName << "\n";

        // 3) Pick the right thunk list
        DWORD thunkRVA  = importDesc.OriginalFirstThunk
                        ? importDesc.OriginalFirstThunk
                        : importDesc.FirstThunk;
        DWORD thunkOffset = RvaToFileOffset(thunkRVA, sections);
        if (thunkOffset == 0) {
            std::cout << "  <cannot locate thunk table>\n";
        } else {
            int      funcCount = 0;
            size_t   entrySize = is64Bit ? sizeof(ULONGLONG) : sizeof(DWORD);

            while (true) {
                // Read the thunk entry
                ULONGLONG raw = 0;
                file.seekg(thunkOffset + funcCount * entrySize, std::ios::beg);
                if (is64Bit) {
                    file.read(reinterpret_cast<char*>(&raw), sizeof(raw));
                } else {
                    DWORD raw32;
                    file.read(reinterpret_cast<char*>(&raw32), sizeof(raw32));
                    raw = raw32;
                }
                if (!file || raw == 0) break;  // end of import list

                ++funcCount;
                ++totalFunctions;

                // Imported by ordinal?
                bool byOrdinal = is64Bit
                    ? (raw & IMAGE_ORDINAL_FLAG64) != 0
                    : (raw & IMAGE_ORDINAL_FLAG32) != 0;

                if (byOrdinal) {
                    WORD ord = static_cast<WORD>(raw & 0xFFFF);
                    std::cout << "  " << std::setw(4) << funcCount
                              << ". Ordinal: " << ord << "\n";
                } else {
                    // Imported by name: raw is RVA of IMAGE_IMPORT_BY_NAME
                    DWORD hintNameRVA = static_cast<DWORD>(raw);
                    DWORD hintNameOffset = RvaToFileOffset(hintNameRVA, sections);
                    if (hintNameOffset) {
                        // skip the 2-byte Hint
                        file.seekg(hintNameOffset + 2, std::ios::beg);
                        std::string funcName;
                        std::getline(file, funcName, '\0');
                        std::cout << "  " << std::setw(4) << funcCount
                                  << ". " << funcName << "\n";
                    }
                }
            }
        }

        std::cout << "-----------------------------\n";

        // 4) Advance to the next descriptor
        descOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    std::cout << "Summary: " << dllCount
              << " DLLs, " << totalFunctions
              << " imported functions\n-----------------------------\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PE file>\n";
        return 1;
    }
    ListImportedFunctions(argv[1]);
    return 0;
}
