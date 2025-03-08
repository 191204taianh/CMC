#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Function to convert RVA to file offset
DWORD RvaToFileOffset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections) {
    for (const auto& section : sections) {
        // Check if the RVA is within this section
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            return (rva - section.VirtualAddress) + section.PointerToRawData;
        }
    }
    return 0; // Not found
}

void ListExportedFunctions(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file!" << std::endl;
        return;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid file format!" << std::endl;
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
    
    // Variables to store export directory information
    DWORD exportDirectoryRVA = 0;
    DWORD exportDirectorySize = 0;
    
    // Read appropriate optional header based on architecture
    bool is64Bit = (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    
    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
    
    if (is64Bit) {
        IMAGE_OPTIONAL_HEADER64 optionalHeader;
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(IMAGE_OPTIONAL_HEADER64));
        
        exportDirectoryRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        IMAGE_OPTIONAL_HEADER32 optionalHeader;
        file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(IMAGE_OPTIONAL_HEADER32));
        
        exportDirectoryRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirectorySize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    
    if (exportDirectoryRVA == 0) {
        std::cout << "No Export Table found." << std::endl;
        return;
    }
    
    // Read section headers
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        file.read(reinterpret_cast<char*>(&sections[i]), sizeof(IMAGE_SECTION_HEADER));
    }
    
    // Convert RVA to file offset for export directory
    DWORD exportDirFileOffset = RvaToFileOffset(exportDirectoryRVA, sections);
    if (exportDirFileOffset == 0) {
        std::cerr << "Failed to locate export directory in file!" << std::endl;
        return;
    }
    
    // Read export directory
    file.seekg(exportDirFileOffset, std::ios::beg);
    IMAGE_EXPORT_DIRECTORY exportDir;
    file.read(reinterpret_cast<char*>(&exportDir), sizeof(IMAGE_EXPORT_DIRECTORY));
    
    // Get module name
    DWORD nameOffset = RvaToFileOffset(exportDir.Name, sections);
    file.seekg(nameOffset, std::ios::beg);
    
    char moduleName[256] = {0};
    file.getline(moduleName, sizeof(moduleName), '\0');
    
    std::cout << "---- EXPORTED FUNCTIONS ----\n";
    std::cout << "Module Name: " << moduleName << std::endl;
    std::cout << "Number of Functions: " << exportDir.NumberOfFunctions << std::endl;
    std::cout << "Number of Named Functions: " << exportDir.NumberOfNames << std::endl;
    
    if (exportDir.NumberOfNames > 0) {
        // Get function names array
        DWORD namesOffset = RvaToFileOffset(exportDir.AddressOfNames, sections);
        
        // Get ordinals array
        DWORD ordinalsOffset = RvaToFileOffset(exportDir.AddressOfNameOrdinals, sections);
        
        // Get function addresses array
        DWORD functionsOffset = RvaToFileOffset(exportDir.AddressOfFunctions, sections);
        
        std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
        std::vector<WORD> ordinals(exportDir.NumberOfNames);
        
        // Read name RVAs
        file.seekg(namesOffset, std::ios::beg);
        file.read(reinterpret_cast<char*>(nameRVAs.data()), exportDir.NumberOfNames * sizeof(DWORD));
        
        // Read ordinals
        file.seekg(ordinalsOffset, std::ios::beg);
        file.read(reinterpret_cast<char*>(ordinals.data()), exportDir.NumberOfNames * sizeof(WORD));
        
        // Display function names and ordinals
        for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
            DWORD nameOffset = RvaToFileOffset(nameRVAs[i], sections);
            file.seekg(nameOffset, std::ios::beg);
            
            char functionName[256] = {0};
            file.getline(functionName, sizeof(functionName), '\0');
            
            // Get function RVA
            file.seekg(functionsOffset + (ordinals[i] * sizeof(DWORD)), std::ios::beg);
            DWORD functionRVA;
            file.read(reinterpret_cast<char*>(&functionRVA), sizeof(DWORD));
            
            std::cout << "  - " << functionName << " (Ordinal: " << (ordinals[i] + exportDir.Base) 
                      << ", RVA: 0x" << std::hex << functionRVA << std::dec << ")" << std::endl;
        }
    }
    
    std::cout << "-----------------------------\n";
    file.close();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PE file>" << std::endl;
        return 1;
    }

    ListExportedFunctions(argv[1]);
    return 0;
}
