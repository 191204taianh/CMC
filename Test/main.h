//
// Created by quanonthecob on 08/04/25.
//

#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <windows.h>
#include "misc.c"

#endif //MAIN_H

#define db 1
#define dw 2
#define dd 4
#define dq 8

// REX prefix indicating 64-bit operand size
#define REX_IF64 if (imageOptionalHeader.Magic == 0x20B) {write_instruction(fr, 0x48);}
