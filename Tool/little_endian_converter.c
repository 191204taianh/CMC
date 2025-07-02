#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_INPUT 256     /* more than enough for most shellcode banners */

/* Pack four bytes into one 32-bit value in little-endian order */
static uint32_t pack4(const char *b)
{
    return  (uint32_t)(unsigned char)b[0]        |
           ((uint32_t)(unsigned char)b[1] <<  8) |
           ((uint32_t)(unsigned char)b[2] << 16) |
           ((uint32_t)(unsigned char)b[3] << 24);
}

int main(void)
{
    char buf[MAX_INPUT+4] = {0};         /* +4 gives room for padding */
    printf("Enter string: ");
    fflush(stdout);

    if (!fgets(buf, sizeof buf, stdin))
        return 1;                        /* I/O error or EOF */

    /* strip trailing newline, if any */
    size_t len = strcspn(buf, "\n");
    buf[len] = '\0';

    /* round length up to a multiple of 4 and pad with NULs */
    size_t padded = (len + 3) & ~3;
    for (size_t i = len; i < padded; ++i)
        buf[i] = '\0';

    puts("\n; ---------- MASM32 output ----------");
    for (size_t off = 0; off < padded; off += 4)
    {
        uint32_t val = pack4(&buf[off]);

        /* Print offset nicely: [esp] for 0, [esp+4] … */
        if (off == 0)
            printf("    mov     dword ptr [esp],    %08Xh ; \"%.4s\"\n",
                   val, &buf[off]);
        else
            printf("    mov     dword ptr [esp+%-2zu], %08Xh ; \"%.4s\"\n",
                   off, val, &buf[off]);
    }
    return 0;
}
