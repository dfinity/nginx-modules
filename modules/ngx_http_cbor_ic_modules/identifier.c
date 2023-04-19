#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "crc32.h"
#include "base32.h"
#include "identifier.h"

// Encodes the ID provided in `input` bytes array with length `len` into human-readable form
// according to the specification: https://internetcomputer.org/docs/current/references/id-encoding-spec
// `output` should be able to hold 63 bytes at most.
unsigned int identifier_encode(const unsigned char *input, size_t len, unsigned char *output)
{
    // ID should be <= 29 bytes
    if (len > 29)
        return 0;

    // Prepare a buffer, max length is 29 + 4 = 33 bytes (crc + input)
    unsigned char buf[33];
    ZERO(buf);

    // Calculate the CRC and add to buffer in big-endian order
    unsigned int crc = crc32(input, len);
    buf[0] = (crc >> 24) & 0xFF;
    buf[1] = (crc >> 16) & 0xFF;
    buf[2] = (crc >> 8) & 0xFF;
    buf[3] = crc & 0xFF;

    // Copy the input into buffer
    for (int i = 0; i < len; i++)
    {
        buf[i + 4] = input[i];
    }

    // Encode base32 into buffer, max length should be 53 bytes
    // This will be a null-terminated string
    unsigned char buf_b32[64];
    ZERO(buf_b32);
    base32_encode(buf, len + 4, buf_b32);

    // Output the base32 string while adding hyphens every 5 chars
    int i = 0, j = 0, k = 0;
    while (buf_b32[i] != 0)
    {
        if (k == 5)
        {
            output[j] = '-';
            j++;
            k = 0;
            continue;
        }

        output[j] = buf_b32[i];
        i++;
        j++;
        k++;
    }

    return j;
}
