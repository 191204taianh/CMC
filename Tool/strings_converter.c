#include <stdio.h>
#include <stdint.h>

#define MAX_OUT 1024

int main(void)
{
    uint32_t val;
    char     out[MAX_OUT];
    size_t   pos = 0;

    puts("Enter hex DWORDs (little-endian) separated by whitespace.\n"
         "Finish with EOF (Ctrl+Z / Ctrl+D):");

    while (scanf("%x", &val) == 1 && pos + 4 < MAX_OUT)
    {
        /* Extract bytes in little-endian order: lowest byte first */
        for (int i = 0; i < 4; ++i)
        {
            unsigned char byte = (val >> (8 * i)) & 0xFF;
            if (byte == 0) {            /* reached padding / end-of-string   */
                out[pos] = '\0';
                printf("\nRecovered string: %s\n", out);
                return 0;
            }
            out[pos++] = (char)byte;
        }
    }

    out[pos] = '\0';
    puts("\nRecovered string:");
    puts(out);
    return 0;
}
