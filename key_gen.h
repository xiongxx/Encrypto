/*********************************************************************
* Filename:   key_gen.h
* Author:     xiongxx
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding generating key for AES implementation.
*********************************************************************/

#ifndef KEY_GEN_H
#define KEY_GEN_H

#include <stddef.h>

//The biggest 64bit prime
#define P 0xffffffffffffffc5ull
#define G 5

#include <stdint.h>
#include <stdlib.h>

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;            // 8-bit byte
typedef unsigned int WORD;             // 32-bit word, change to "long" for 16-bit machines



static inline uint64_t mul_mod_p(uint64_t a, uint64_t b);

static inline uint64_t pow_mod_p(uint64_t a, uint64_t b);

uint64_t powmodp(uint64_t a, uint64_t b);

uint64_t randomint64();

uint64_t secret_64_bit();

BYTE* secret_generator();

void print_hex(BYTE str[], int len); 

#endif
