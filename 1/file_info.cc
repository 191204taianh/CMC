#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>  // Thêm thư viện để xử lý chuỗi an toàn

template<typename T>
void print_field(const std::string& name, T value) {
    std::cout << std::left << std::setw(30) << name
              << "| " << std::right << std::setw(12) << std::dec << static_cast<uint64_t>(value)
              << " | 0x" << std::hex << static_cast<uint64_t>(value) << std::endl;
}

void PrintPEInfo(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file!" << std::endl;
        return;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid PE file!" << std::endl;
        return;
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS32));

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Cannot find PE header!" << std::endl;
        return;
    }

    // std::cout << "---- PE FILE INFO ----\n";
    // std::cout << "Signature: " << ntHeaders.Signature << std::endl;
    // std::cout << "Machine: " << std::hex << ntHeaders.FileHeader.Machine << std::endl;
    // std::cout << "Number of Symbols: " << ntHeaders.FileHeader.NumberOfSymbols << std::endl;
    // std::cout << "Time Date Stamp: " << std::dec << ntHeaders.FileHeader.TimeDateStamp << std::endl;
    // std::cout << "Size of Optional Header: " << ntHeaders.FileHeader.SizeOfOptionalHeader << std::endl;
    // std::cout << "Characteristics: 0x" << std::hex << ntHeaders.FileHeader.Characteristics << std::endl;
    // std::cout << "Magic: 0x" << std::hex << ntHeaders.OptionalHeader.Magic << std::endl;
    // std::cout << "Major Linker Version: " << static_cast<int>(ntHeaders.OptionalHeader.MajorLinkerVersion) << std::endl;
    // std::cout << "Minor Linker Version: " << static_cast<int>(ntHeaders.OptionalHeader.MinorLinkerVersion) << std::endl;
    // std::cout << "Size of Code: 0x" << std::hex << ntHeaders.OptionalHeader.SizeOfCode << std::endl;
    // std::cout << "Size of Initialized Data: 0x" << std::hex << ntHeaders.OptionalHeader.SizeOfInitializedData << std::endl;
    // std::cout << "Number of Sections: " << ntHeaders.FileHeader.NumberOfSections << std::endl;
    // std::cout << "Pointer to Entry Point: 0x" << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;
    // std::cout << "Image Base: 0x" << std::hex << static_cast<uint64_t>(ntHeaders.OptionalHeader.ImageBase) << std::endl;
    // std::cout << "File Alignment: 0x" << std::hex << ntHeaders.OptionalHeader.FileAlignment << std::endl;
    // std::cout << "Section Alignment: 0x" << std::hex << ntHeaders.OptionalHeader.SectionAlignment << std::endl;
    // std::cout << "Size of Image: 0x" << std::hex << ntHeaders.OptionalHeader.SizeOfImage << std::endl;
    // std::cout << "Import Data Directory: 0x" << std::hex << ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;
    // std::cout << "Export Directory: 0x" << std::hex << ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress << std::endl;

    print_field("Signature", ntHeaders.Signature);
    print_field("Machine", ntHeaders.FileHeader.Machine);
    print_field("Number of Symbols", ntHeaders.FileHeader.NumberOfSymbols);
    print_field("Time Date Stamp", ntHeaders.FileHeader.TimeDateStamp);
    print_field("Size of Optional Header", ntHeaders.FileHeader.SizeOfOptionalHeader);
    print_field("Characteristics", ntHeaders.FileHeader.Characteristics);
    print_field("Magic", ntHeaders.OptionalHeader.Magic);
    if (ntHeaders.OptionalHeader.Magic == 0x10b) {
        printf(" --> Magic: PE32 (32-bit)\n");
    }
    else if (ntHeaders.OptionalHeader.Magic == 0x20b) {
        printf(" --> Magic: PE32+ (64-bit)\n");
    } else {
        printf(" --> Magic: Unknown (0x%x)\n", ntHeaders.OptionalHeader.Magic);
    }
    print_field("DOS Magic", dosHeader.e_magic);
    print_field("Major Linker Version", ntHeaders.OptionalHeader.MajorLinkerVersion);
    print_field("Minor Linker Version", ntHeaders.OptionalHeader.MinorLinkerVersion);
    print_field("Size of Code", ntHeaders.OptionalHeader.SizeOfCode);
    print_field("Size of Initialized Data", ntHeaders.OptionalHeader.SizeOfInitializedData);
    print_field("Number of Sections", ntHeaders.FileHeader.NumberOfSections);
    print_field("Pointer to Entry Point", ntHeaders.OptionalHeader.AddressOfEntryPoint);
    print_field("Image Base", ntHeaders.OptionalHeader.ImageBase);
    print_field("File Alignment", ntHeaders.OptionalHeader.FileAlignment);
    print_field("Section Alignment", ntHeaders.OptionalHeader.SectionAlignment);
    print_field("Size of Image", ntHeaders.OptionalHeader.SizeOfImage);
    print_field("Import Directory VA", ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    print_field("Export Directory VA", ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    std::cout << "\n---- SECTION HEADERS ----\n";
    file.seekg(dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32), std::ios::beg);

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));

        // Đọc tên section một cách an toàn
        char sectionName[9] = {0};  // Tạo chuỗi 9 ký tự (8 ký tự + null terminator)
        std::memcpy(sectionName, sectionHeader.Name, 8);  // Sao chép an toàn

        std::cout << "Section Name: " << sectionName << std::endl;
        std::cout << "Characteristics: 0x" << std::hex << sectionHeader.Characteristics << std::endl;
        std::cout << "Raw Address: 0x" << std::hex << sectionHeader.PointerToRawData << std::endl;
        std::cout << "Raw Size: 0x" << std::hex << sectionHeader.SizeOfRawData << std::endl;
        std::cout << "Virtual Address: 0x" << std::hex << sectionHeader.VirtualAddress << std::endl;
        std::cout << "Virtual Size: 0x" << std::hex << sectionHeader.Misc.VirtualSize << std::endl;
        std::cout << "-------------------------------\n";
    }

    file.close();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <PE file>" << std::endl;
        return 1;
    }

    PrintPEInfo(argv[1]);
    return 0;
}
