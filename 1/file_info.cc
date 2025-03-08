#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>  // Thêm thư viện để xử lý chuỗi an toàn

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

    std::cout << "---- PE FILE INFO ----\n";
    std::cout << "Number of Sections: " << ntHeaders.FileHeader.NumberOfSections << std::endl;
    std::cout << "Pointer to Entry Point: 0x" << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "Image Base: 0x" << std::hex << static_cast<uint64_t>(ntHeaders.OptionalHeader.ImageBase) << std::endl;
    std::cout << "File Alignment: 0x" << std::hex << ntHeaders.OptionalHeader.FileAlignment << std::endl;
    std::cout << "Section Alignment: 0x" << std::hex << ntHeaders.OptionalHeader.SectionAlignment << std::endl;
    std::cout << "Size of Image: 0x" << std::hex << ntHeaders.OptionalHeader.SizeOfImage << std::endl;
    std::cout << "Import Data Directory: 0x" << std::hex << ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;
    std::cout << "Export Directory: 0x" << std::hex << ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress << std::endl;

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
