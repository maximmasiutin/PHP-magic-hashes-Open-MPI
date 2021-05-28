/*
SHA1 implementation using the CPU instructions (sha1msg1, sha1msg2, sha1rnds4, sha1nexte) is written by Jeffrey Walton.
Taken from the the Jeffrey Walton's (noloader) GitHub page at https://github.com/noloader/SHA-Intrinsics/blob/master/sha1-x86.c

SHA1 implementation using the pure C (when no the CPU is not equipped with the the SHA instructions) is written by Steve Reid.
Taken from the "clibs" GitHub page at https://github.com/clibs/sha1

*/



/* ================ sha1.h ================ */
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#include <string>

#ifndef DISABLE_SHA_CPU_EXTENSIONS
#define USE_SHA_CPU_EXTENSIONS
#endif


// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif


typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, uint32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
