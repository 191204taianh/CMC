#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

// Convert Relative Virtual Address (RVA) to File Offset
DWORD RvaToFileOffset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections) {
    for (const auto& section : sections) {
        // Check if the RVA is within this section
        if (rva >= section.VirtualAddress && 
            rva < section.VirtualAddress + section.Misc.VirtualSize) {
            return (rva - section.VirtualAddress) + section.PointerToRawData;
        }
    }
    return 0; // Not found
}

void ListImportedFunctions(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        return;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid PE file format!" << std::endl;
        return;
    }

    // Move to PE header
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    
    // Read NT signature
    DWORD ntSignature;
    file.read(reinterpret_cast<char*>(&ntSignature), sizeof(DWORD));
    
    if (ntSignature != IMAGE_NT_SIGNATURE) {
        std::cerr << "PE header not found!" << std::endl;
        return;
    }
    
    // Read File Header to determine if it's 32-bit or 64-bit
    IMAGE_FILE_HEADER fileHeader;
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER));
    
    // Variables to store import directory information
    DWORD importDirectoryRVA = 0;
    DWORD importDirectorySize = 0;
    
    // Read appropriate optional header based on architecture
    bool is64Bit = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    
    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    
    if (is64Bit) {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(IMAGE_OPTIONAL_HEADER64));
        
        importDirectoryRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        IMAGE_OPTIONAL_HEADER32 optionalHeader;
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(IMAGE_OPTIONAL_HEADER32));
        
        importDirectoryRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    
    if (importDirectoryRVA == 0) {
        std::cout << "No Import Table found." << std::endl;
        return;
    }
    
    // Read section headers
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        file.read(reinterpret_cast<char*>(&sections[i]), sizeof(IMAGE_SECTION_HEADER));
    }
    
    // Convert RVA to file offset for import directory
    DWORD importDirFileOffset = RvaToFileOffset(importDirectoryRVA, sections);
    if (importDirFileOffset == 0) {
        std::cerr << "Failed to locate import directory in file!" << std::endl;
        return;
    }
    
    // Read import descriptors
    file.seekg(importDirFileOffset, std::ios::beg);
    IMAGE_IMPORT_DESCRIPTOR importDesc;

    std::cout << "---- IMPORTED FUNCTIONS ----\n";
    std::cout << "File: " << filename << (is64Bit ? " (64-bit)" : " (32-bit)") << std::endl;
    std::cout << "-----------------------------\n";

    int dllCount = 0;
    int totalFunctions = 0;

    while (true) {
        file.read(reinterpret_cast<char*>(&importDesc), sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (importDesc.Name == 0) break; // End of Import Table

        DWORD dllNameOffset = RvaToFileOffset(importDesc.Name, sections);
        if (dllNameOffset == 0) continue;

        file.seekg(dllNameOffset, std::ios::beg);
        char dllName[256] = {0};
        file.getline(dllName, sizeof(dllName), '\0');
        
        dllCount++;
        std::cout << "DLL #" << dllCount << ": " << dllName << std::endl;

        // Use OriginalFirstThunk if available, otherwise use FirstThunk
        DWORD thunkRVA = importDesc.OriginalFirstThunk ? importDesc.OriginalFirstThunk : importDesc.FirstThunk;
        DWORD thunkOffset = RvaToFileOffset(thunkRVA, sections);
        if (thunkOffset == 0) continue;

        file.seekg(thunkOffset, std::ios::beg);
        
        int functionCount = 0;

        while (true) {
            // Read thunk data based on architecture
            ULONGLONG thunkData = 0;
            if (is64Bit) {
                file.read(reinterpret_cast<char*>(&thunkData), sizeof(ULONGLONG));
                if (thunkData == 0) break; // End of function list
            } else {
                DWORD thunk32;
                file.read(reinterpret_cast<char*>(&thunk32), sizeof(DWORD));
                if (thunk32 == 0) break; // End of function list
                thunkData = thunk32;
            }

            functionCount++;
            totalFunctions++;

            // Check if import by ordinal
            if ((is64Bit && (thunkData & IMAGE_ORDINAL_FLAG64)) || 
                (!is64Bit && (thunkData & IMAGE_ORDINAL_FLAG32))) {
                
                WORD ordinal = is64Bit ? (thunkData & 0xFFFF) : (thunkData & 0xFFFF);
                std::cout << "  " << std::setw(4) << functionCount << ". " 
                          << "Ordinal: " << ordinal << std::endl;
            } else {
                // Import by name
                DWORD nameRVA = static_cast<DWORD>(thunkData);
                DWORD nameOffset = RvaToFileOffset(nameRVA, sections);
                if (nameOffset == 0) continue;

                // Skip the Hint (2 bytes)
                file.seekg(nameOffset + 2, std::ios::beg);
                
                char functionName[256] = {0};
                file.getline(functionName, sizeof(functionName), '\0');
                
                std::cout << "  " << std::setw(4) << functionCount << ". " 
                          << functionName << std::endl;
            }

            // Return to the next thunk entry
            file.seekg(thunkOffset + (functionCount * (is64Bit ? sizeof(ULONGLONG) : sizeof(DWORD))), std::ios::beg);
        }
        std::cout << "-----------------------------\n";
    }

    std::cout << "Summary: " << dllCount << " DLLs, " << totalFunctions << " imported functions\n";
    std::cout << "-----------------------------\n";
    file.close();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PE file>" << std::endl;
        return 1;
    }

    ListImportedFunctions(argv[1]);
    return 0;
}
