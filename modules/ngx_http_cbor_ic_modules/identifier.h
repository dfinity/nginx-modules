#include <string.h>

#define ZERO(x) memset(x, 0, sizeof(x))
unsigned int identifier_encode(const unsigned char *input, size_t len, unsigned char *output);
