#include <stdio.h>

// Short CRC32 implementation without lookup tables
// For <=29 byte arrays it's fast enough
unsigned int crc32(const unsigned char *message, size_t len)
{
    unsigned int byte, crc, mask;

    crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
    {
        byte = message[i];
        crc = crc ^ byte;

        for (int j = 7; j >= 0; j--)
        {
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }

    return ~crc;
}
