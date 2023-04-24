#include <stdio.h>

// Short CRC32 implementation without lookup tables
// For <=29 byte arrays it's fast enough
unsigned int ic_crc32(const unsigned char *message, size_t len)
{
    unsigned int crc = 0xFFFFFFFF, mask = 0;

    for (size_t i = 0; i < len; i++)
    {
        crc ^= message[i];

        for (int j = 7; j >= 0; j--)
        {
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }

    return ~crc;
}
