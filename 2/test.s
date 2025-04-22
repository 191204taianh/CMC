.586
.model flat, stdcall
option casemap :none

include windows.inc
include user32.inc
include lib user32.lib

.code
start:
    push 0
    push offset message
    push offset title
    push 0
    call MessageBoxA
    jmp original_entry_point

message db "Infected!", 0
title db "Infected", 0

original_entry_point dd 0

end start
