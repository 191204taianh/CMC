#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>

// Function to find closest value of FileAlignment that's more than the section's size
ULONGLONG closest(DWORD actual, DWORD alignment) {
    return alignment * ceil((double) actual / alignment);
}

void debug(unsigned char *array, int size) {
    if (size == 0)
        // Print until \0
        for (int i = 0; array[i] == 0; i++)
            printf("%02x ", array[i]);
    else
        for (int i = 0; i < size; i++)
            printf("%02x ", array[i]);
    printf("\n");
}

int end(FILE *stream, int status) {
    // To close the file stream before terminating the programme
    fclose(stream);
    printf("\n");
    exit(status);
}

ULONGLONG hextoint(BYTE *input, int size) {
    // Convert from hex array to int
    ULONGLONG var = 0;
    for (int i = 0; i < size; i++) {
        ULONGLONG temp = input[i];
        var = var | temp << (i * 8);
    }
    return var;
}

// Read AND convert to unsigned long long type
ULONGLONG getval(FILE *stream, int length, int whence, DWORD offset) {
    BYTE input[length];
    fseek(stream, offset, whence);
    fread(input, 1, length, stream);
    hextoint(input, length);
    // No return but this still works?
}

void setval_char(FILE *stream, char *data, int length, int whence, DWORD offset) {
    fseek(stream, offset, whence);
    for (int i = 0, term = 0; i < length; ++i)
        if (term != 0) {
            fwrite('\0', 1, 1, stream);
        } else if (data + i != 0) {
            fwrite(data + i, 1, 1, stream);
        } else {
            term = 1;
            fwrite('\0', 1, 1, stream);
        }
    // Write until end of string (termination \0)
    // Insert \0 after end of string until length is reached
}

void setval_int(FILE *stream, ULONGLONG data, int length, int whence, DWORD offset) {
    fseek(stream, offset, whence);
    fwrite(&data, 1, length, stream);
}

void write_instruction(FILE *stream, int instruction) {
    // Big-endian writing
    for (int i = instruction <= 0xFF ? 0 : instruction <= 0xFFFF ? 1 : instruction <= 0xFFFFFF ? 2 : 3; i >= 0; i--) {
        // Byte-by-byte writing
        fwrite((char *) &instruction + i, 1, 1, stream);
    }
}

void instruct(FILE *stream, DWORD instruction, DWORD value, short vallen) {
    write_instruction(stream, instruction);

    // Check if value is char (1 byte) or int (4 bytes)
    // Little-endian writing
    fwrite(&value, vallen, 1, stream);
}

void pad(FILE *stream, int length) {
    for (int i = 0; i < length; ++i) {
        fputc(0, stream);
    }
}
