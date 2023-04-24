#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "base32.h"
#include "crc32.h"
#include "identifier.h"

// Some test IDs from https://internetcomputer.org/docs/current/references/id-encoding-spec#test-vectors
char src1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08};

char src2[] = {0x00};

char src3[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29};

char src4[] = {0xab, 0xcd, 0x01};

void test_crc32()
{
    unsigned int crc = ic_crc32("123456789", 9);
    assert(crc == 0xcbf43926);

    crc = ic_crc32("", 0);
    assert(crc == 0x0);
}

void test_base32()
{
    char buf[64];

    ZERO(buf);
    base32_encode(src1, sizeof(src1), buf);
    assert(strcmp(buf, "aaaqeayeaudaoca") == 0);

    ZERO(buf);
    base32_encode(src2, sizeof(src2), buf);
    assert(strcmp(buf, "aa") == 0);

    ZERO(buf);
    base32_encode(src3, sizeof(src3), buf);
    assert(strcmp(buf, "aebagbafaydqqciqcejbgfavcylrqgjaeercgjbfeytsqki") == 0);
}

void test_identifier_encode()
{
    char buf[64];

    ZERO(buf);
    unsigned int len = identifier_encode(src1, sizeof(src1), buf);
    assert(len == 25);
    assert(strcmp(buf, "xtqug-aqaae-bagba-faydq-q") == 0);

    ZERO(buf);
    len = identifier_encode("", 0, buf);
    assert(len == 8);
    assert(strcmp(buf, "aaaaa-aa") == 0);

    ZERO(buf);
    len = identifier_encode(src2, sizeof(src2), buf);
    assert(len == 9);
    assert(strcmp(buf, "2ibo7-dia") == 0);

    ZERO(buf);
    len = identifier_encode(src3, sizeof(src3), buf);
    assert(len == 63);
    assert(strcmp(buf, "iineg-fibai-bqibi-ga4ea-searc-ijrif-iwc4m-bsibb-eirsi-jjge4-ucs") == 0);

    ZERO(buf);
    len = identifier_encode(src4, sizeof(src4), buf);
    assert(len == 14);
    assert(strcmp(buf, "em77e-bvlzu-aq") == 0);

    // Too long input yields empty string
    ZERO(buf);
    len = identifier_encode(src3, 30, buf);
    assert(len == 0);
    assert(strcmp(buf, "") == 0);
}

int main()
{
    test_crc32();
    test_base32();
    test_identifier_encode();
}
