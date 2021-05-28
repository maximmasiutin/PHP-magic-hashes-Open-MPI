/*
PHP-magic-hashes-Open-MPI
Copyright 2021 Maxim Masiutin <maxim@masitin.com>
All rights reserved

Version 1.0.
May 28, 2021.

An Open MPI application to look for PHP Magic Hashes using distributed computing. 
It hashes multiple messages with SHA-1 until a hash is found that matches the definition of a PHP Magic Hash.
A PHP magic hash is a hash that in hexadecimal form starts with 0e and then has only decimal digits, e.g., 0e26379374770352024666148968868586665768.
See the "phpmagic_sha1.php" file for some of the messages found that produce PHP Magic Hashes if hashed with SHA-1. Here are a few of such hashes.

1023456852390915        0e26379374770352024666148968868586665768
lowercasegzmgqmx        0e46257280787231943618306073689855362607
lowercasifdvqkfr        0e11372668415308535558155136274413213182
lowercasebchqcwctky     0e63270019212961791900055698786302314274
lowercaseabcsobpkrt     0e54706107047262165256262457226759421225
UPPERCASFFLIIQWR        00e0209539108131630074694125235505223102
MixedCaseERWqTVQ        0e26765837881628507475765845815158037783
MixCaseDigJiRR9d        00e6970695351422324349039381794949865825
Punctuati0t..jsI        0e77237948969014118794910091659528041921
Punc!0"*!"#$8!zv        0e77726009946581613829608157794165640009
UTM!1k345678fNzG        0e60098992377811189363030093264003550414
Maxim!3M3457WL8N        0e56563987203581868006812012373581596907
SI201M!2M34FUN"s        0e56771164582932122522008085807868856600
Punctu!U"F5ru   	0e10005769841271999406141555258742283712
Punc!0!v!%X&H   	0e46022419093253497711357929642317161144
Punc!0"5!%N/J/  	0e23361421882052104970353750698818490573
Punc!0"/!"#Z"f# 	0e62673103166046521233198723999648604397
Punctuatiow$'l9X        0e16039695246683143323677708220808911326
Anastasia!$3j6CE        0e39502544098047582971721681103284862230
Anastasia"D#L3R"        0e38695756209930671587956403047252377646

The Open MPI interface allows looking for a the PHP Magic Hash in parallel, using multiple different distributed processors.
The application should be individually compiled on each target processor to take the benefits of these particular processors (optimizations, instruction sets, SHA-1 CPU instructions, if available, etc.). You can use tools like Ansible to automate the tasks.
Although GPUs calculate hashes very quickly, this application can be useful for clusters which have no GPU but have computing time available. 
For example, on 14 servers with a total of 106 cores of various processors manufactured between 2014 and 2017, some of which support SHA-1 CPU instructions and some not, with a combined Passmark CPU mark of 111706, it usually takes 2-10 seconds to find a PHP Magic Hash.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>

SHA1 implementation using the CPU instructions (sha1msg1, sha1msg2, sha1rnds4, sha1nexte) is written by Jeffrey Walton.
Taken from the Jeffrey Walton's (noloader) GitHub page at <https://github.com/noloader/SHA-Intrinsics/blob/master/sha1-x86.c>

SHA1 implementation using the pure C (when no the CPU is not equipped with the SHA instructions) is written by Steve Reid.
Taken from the "clibs" GitHub page at <https://github.com/clibs/sha1>

*/

#ifndef DISABLE_MPI
#include <mpi.h>
#endif
#include <string>
#include <iostream>
#include <chrono>

// We currently support only SHA-1 hash with a digest size of 20 bytes
#include "sha1.h"
const unsigned int CDigestLength = 20;


// CONFIGURATION SECTION #################################################################################################################################

// Define just one of the following **********************************************************************************************************************
//#define digits_only
//#define lowercase_only
//#define uppercase_only
//#define mixed_case_only
//#define mixed_case_with_digits
#define mixcase_digits_punct

// *******************************************************************************************************************************************************
// Define the "stepover_run" for a slower mode when all the processors start from the same base plus the current processor number 
// and increment by the total number of processors on each steps. However, it does not require to have a prefix with the 
// current processor number in the middle of the message.
// If you would not define the "stepover_run", each process will start from it's own base and will increment by just one; however
// if the message is short, the incremented value may overflow the processors's number prefix, so all the processors witll be
// calculating the same data
//#define stepover_run

// The lenght of the message to be hashed ***************************************************************************************************************
const unsigned int CMessageLen = 16;

// Define this if you need the Open MPI to continue finding matches after finding the first match *******************************************************
//#define mpi_continue

// END OF CONFIGURATION SECTION #########################################################################################################################



#ifdef digits_only
const unsigned char CInitialChar = '0';
#endif

#ifdef lowercase_only
const unsigned char CInitialChar = 'a';
#endif

#ifdef uppercase_only
const unsigned char CInitialChar = 'A';
#endif

#ifdef mixed_case_only
const unsigned char CInitialChar = 'A';
#endif

#ifdef mixed_case_with_digits
const unsigned char CInitialChar = '0';
#endif

#ifdef mixcase_digits_punct
const unsigned char CInitialChar = '!';
#endif

const unsigned int CMpiAbortCode = 0;
const unsigned char CChar00 = 0x00;
const unsigned char CChar0E = 0x0e;
const unsigned char CCharE1 = 0xe1;
const unsigned char CChar09 = 0x09;
const unsigned char CChar90 = 0x90;

static bool is_digit_byte(const unsigned char b)
{
    return ((b & 0xf) <= 9) && ((b >> 4) <= 9);
}

static bool is_edigit_byte(const unsigned char b)
{
    return ((b & 0xf) <= 9) && ((b >> 4) == CChar0E);
}

// we use branching here rather than the logical operations over the whole 64-bit qwords, because it is very infrequent that the algorithm gets to here

static bool is_phpmagic_4up(const unsigned char b[CDigestLength])
{
    return
        (is_digit_byte(b[4])) &&
        (is_digit_byte(b[5])) &&
        (is_digit_byte(b[6])) &&
        (is_digit_byte(b[7])) &&
        (is_digit_byte(b[8])) &&
        (is_digit_byte(b[9])) &&
        (is_digit_byte(b[10])) &&
        (is_digit_byte(b[11])) &&
        (is_digit_byte(b[12])) &&
        (is_digit_byte(b[13])) &&
        (is_digit_byte(b[14])) &&
        (is_digit_byte(b[15])) &&
        (is_digit_byte(b[16])) &&
        (is_digit_byte(b[17])) &&
        (is_digit_byte(b[18])) &&
        (is_digit_byte(b[19])); 
}

bool is_nothex_from_b3(const unsigned char b[CDigestLength])
{
    return ((is_digit_byte(b[3])) &&
        is_phpmagic_4up(b));
}

bool is_from_b2_after_zero(const unsigned char b[CDigestLength])
{
    unsigned char b2 = b[2];
    unsigned char b3;
    switch (b2)
    {
    case CChar0E:
        return is_nothex_from_b3(b);
    case CChar00:
        b3 = b[3];
        if ((b3 == CChar0E) || (is_edigit_byte(b3)))
            return is_phpmagic_4up(b);
        else
            return false;
    default:
        if (is_edigit_byte(b2))
            return
            is_nothex_from_b3(b);
        else
            return false;
    }
}


// We use branching to check whether the buffer fits the definition of "PHP Magic".
// We do not use logical operations over the whole 64-bit qwords.
// There is only 1/128 chance (0.78125%) that we move past the first byte - it can be either 00 or 0e from the whole range of 256 bytes,
// and if the first byte was 00, we have have only 1 / (256/12) chance (4.6875%) that we move past the second byte, etc.
// So, in most cases, checking just first or the second byte should be enough to continue the loop and check for new digests.


static bool is_phpmagic_buf(const unsigned char b[CDigestLength])
{
    unsigned char b1;
    switch (b[0])
    {
    case CChar0E:
        return ((is_digit_byte(b[1])) && (is_digit_byte(b[2])) && is_nothex_from_b3(b));
    case CChar00:
        b1 = b[1];
        switch (b1)
        {
        case CChar0E:
            return ((is_digit_byte(b[2])) && is_nothex_from_b3(b));
        case CChar00:
            return is_from_b2_after_zero(b);
        default:
            if (is_edigit_byte(b1))
                return ((is_digit_byte(b[2])) && is_nothex_from_b3(b));

            else
                return false;
        }
    default:
        return false;
    }
}

static void increment_char_mixedcase_with_digits(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case '9':
            a = 'A';
            break;
        case 'Z':
            a = 'a';
            break;
        case 'z':
            a = '0';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_mixedcase_with_digits_and_punctuation(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case '9':
            a = 'A';
            break;
        case 'Z':
            a = 'a';
            break;
        case 'z':
            a = '!';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}


static void increment_char_mixedcase(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case 'Z':
            a = 'a';
            break;
        case 'z':
            a = 'A';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_uppercase(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case 'Z':
            a = 'A';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_lowercase(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case 'z':
            a = 'a';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_digits(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case '9':
            a = '0';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_hexadecimal_lowercase(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case '9':
            a = 'a';
            break;
        case 'z':
            a = '0';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_hexadecimal_uppercase(unsigned char* c)
{
    while (true)
    {
        unsigned char a = *c;
        switch (a)
        {
        case '9':
            a = 'A';
            break;
        case 'Z':
            a = '0';
            *c = a;
            --c;
            continue;
        default:
            ++a;
        }
        *c = a;
        break;
    }
}

static void increment_char_short(unsigned char* c)
{
#ifdef digits_only
    increment_char_digits(c);
#endif
#ifdef mixcase_digits_punct
    increment_char_mixedcase_with_digits_and_punctuation(c);
#endif
#ifdef lowercase_only
    increment_char_lowercase(c);
#endif
#ifdef uppercase_only
    increment_char_uppercase(c);
#endif
#ifdef mixed_case_only
    increment_char_mixedcase(c);
#endif
#ifdef mixed_case_with_digits
    increment_char_mixedcase_with_digits(c);
#endif
}




int main(int argc, char* argv[])
{

#ifndef DISABLE_MPI

    MPI_Init(NULL, NULL);

    int mpi_result;
    int mpi_total = 0;
    mpi_result = MPI_Comm_size(MPI_COMM_WORLD, &mpi_total);
    if (mpi_result != MPI_SUCCESS)
    {
        std::cerr << "MPI_Comm_size error " << mpi_result;
        return 1;
    }

    int mpi_current = 0;
    mpi_result = MPI_Comm_rank(MPI_COMM_WORLD, &mpi_current);
    if (mpi_result != MPI_SUCCESS)
    {
        std::cerr << "MPI_Comm_rank error " << mpi_result;
        return 1;
    }
    std::string processor_name;
    {
        char processor_name_buf[MPI_MAX_PROCESSOR_NAME];
        memset(processor_name_buf, 0, sizeof(processor_name_buf));
        int name_len = 0;
        mpi_result = MPI_Get_processor_name(processor_name_buf, &name_len);
        if (mpi_result != MPI_SUCCESS)
        {
            std::cerr << "MPI_Get_processor_name error " << mpi_result;
            return 1;
        }
        if ((name_len <= 0) || (name_len > sizeof(processor_name_buf)))
        {
            std::cerr << "Invalid length of the processor name: " << name_len;
            return 1;
        }
        std::string::size_type nl = name_len;
        char* bufptr = &(processor_name_buf[0]);
        processor_name.assign(bufptr, nl);
    }

#else
    const std::string processor_name("Test");
    int mpi_current = 0;
    int mpi_total = 1;
#endif

#ifdef digits_only
    std::string message("1");
#endif
#ifdef mixcase_digits_punct
    std::string message("MixC!0");
#endif
#ifdef lowercase_only
    std::string message("lowercase");
#endif
#ifdef uppercase_only
    std::string message("UPPERCASE");
#endif
#ifdef mixed_case_only
    std::string message("MixedCase");
#endif
#ifdef mixed_case_with_digits
    std::string message("MixCaseDig0");
#endif

    std::string next_message;

#ifndef stepover_run
    {
        const unsigned int CSuffixLength = 100;
        unsigned char suffix[CSuffixLength];
        memset(suffix, CInitialChar, sizeof(suffix));
        const char* charptr = (char*)&(suffix[CSuffixLength - 1]);
        for (int i = 0; i < mpi_current; ++i)
        {
            increment_char_short((unsigned char*)charptr);
            if (suffix[1] != CInitialChar)
            {
                std::cerr << "Stepover buffer overflow" << std::endl;
                return 1;
            }
        }
        int len = 0;
        while (*charptr != CInitialChar)
        {
            ++len;
            --charptr;
        }
        ++charptr;
        if (len>0)
            message.append(charptr, len);
    }
#endif

    char c = CInitialChar;
    while (message.length() < CMessageLen)
    {
        unsigned char buff[2];
        buff[0] = CInitialChar;
        buff[1] = c;
        {
            const char* charptr = (char*)&(buff[1]);
            message.append(charptr, 1);
        }
        increment_char_short(&buff[1]);
        c = buff[1];
    }

#ifdef hash_is_sha256
    SHA256 sha256;
#endif    
#ifdef hash_is_sha1
    SHA1_CTX sha1ctx;
#endif    
    unsigned char buf[CMessageLen];
    unsigned char hash[CDigestLength];
    memset(&(buf[0]), 0, sizeof(buf));
    std::string::size_type sl = message.length();
    if (sl > sizeof(buf))
    {
        std::cerr << "The string '" << message << "' has " << sl << " characters is loo long to fit in the "<< CMessageLen <<"-bytes buffer";
        return 1;
    }

    memcpy(&(buf[0]), message.c_str(), sl);

    std::string common_initial_message = message;

#ifdef stepover_run
    for (int i = 0; i < mpi_current; ++i)
    {
        increment_char_short(&(buf[CMessageLen - 1]));
    }
    {
        char* charptr = (char*)&(buf[0]);
        message.assign(charptr, sl);
    }
    {
        unsigned char next_buf[CMessageLen];
        memcpy(next_buf, buf, CMessageLen);
        for (int i = 0; i < mpi_total; ++i)
        {
            increment_char_short(&(next_buf[CMessageLen - 1]));
        }
        {
            const char* charptr = (char*)&(next_buf[0]);
            next_message.assign(charptr, sl);
        }
    }
#else
    {
        unsigned char next_buf[CMessageLen];
        memcpy(next_buf, buf, CMessageLen);
        increment_char_short(&(next_buf[CMessageLen - 1]));
        const char* charptr = (char*)&(next_buf[0]);
        next_message.assign(charptr, sl);

    }
#endif


#ifdef stepover_run
    std::cout << "Stepover mode. Common initial message: '" << common_initial_message << "', initial message for processor " << mpi_current <<" ("<<processor_name<<"): '" << message << "', step: " << mpi_total << ", next message: '"<< next_message << "'" << std::endl;
#else
    std::cout << "Quick sequential mode. Base message for processor " << mpi_current << " ("<<processor_name<<"): '" << message << "', next message: '" << next_message << "'."<<std::endl;
#endif

    auto time_begin = std::chrono::high_resolution_clock::now();

    while (true)
    {
#ifdef hash_is_sha256
        sha256.add(&(buf[0]), CMessageLen);
        sha256.getHash(hash);
#endif
#ifdef hash_is_sha1
        SHA1Init(&sha1ctx);
        SHA1Update(&sha1ctx, &(buf[0]), CMessageLen);
        SHA1Final(&(hash[0]), &sha1ctx);
#endif

        if (is_phpmagic_buf(hash))
        {
            auto time_end = std::chrono::high_resolution_clock::now();
            auto duration_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_begin);
            auto ms_count = duration_milliseconds.count();
            {
                const char* charptr = (char*)&(buf[0]);
                message.assign(charptr, CMessageLen);
            }

            std::cout << "PHP Magic string found!!!" << std::endl;
            std::cout << "It took " << ms_count << " milliseconds" << std::endl;

            // convert to hex string
            std::string hash_code;
            hash_code.reserve(2 * CDigestLength);
            static const char dec2hex[16 + 1] = "0123456789abcdef";
            for (int i = 0; i < CDigestLength; i++)
            {
                hash_code += dec2hex[(hash[i] >> 4) & 15];
                hash_code += dec2hex[hash[i] & 15];
            }

            std::cout << "Solution: '" << message << "' found by the processor " << mpi_current << " ("<<processor_name<<") of " << mpi_total << ", hash: " << hash_code << std::endl;

#ifndef mpi_continue
#ifndef DISABLE_MPI
            if (mpi_total > 1)
            {
                mpi_result = MPI_Abort(MPI_COMM_WORLD, CMpiAbortCode);
                if (mpi_result != MPI_SUCCESS)
                {
                    std::cerr << "MPI_Abort error " << mpi_result;
                }
            }
#endif
            break;

#endif
        }
#ifdef stepover_run
        for (int i = 0; i < mpi_total; ++i)
        {
            increment_char_short(&(buf[CMessageLen - 1]));
        }
#else
        increment_char_short(&(buf[CMessageLen - 1]));
#endif
    }
#ifndef DISABLE_MPI

    MPI_Finalize();
#endif

    return 0;
}
