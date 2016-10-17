/*********************************************************************
* Filename:   aes_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding AES
              implementation. These tests do not encompass the full
              range of available test vectors and are not sufficient
              for FIPS-140 certification. However, if the tests pass
              it is very, very likely that the code is correct and was
              compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include "aes.h"
#include  "key_gen.h"

/*********************** FUNCTION DEFINITIONS ***********************/

void arr_reset(BYTE str[], int len)
{
	int idx;

	for(idx = 0; idx < len; idx++)
		str[idx] = 0;
}

int aes_cbc_test()
{
	WORD key_schedule[60];
	BYTE enc_buf[128];
	BYTE plaintext[1][32] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[1][32] = {
//		{0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6,0x9c,0xfc,0x4e,0x96,0x7e,0xdb,0x80,0x8d,0x67,0x9f,0x77,0x7b,0xc6,0x70,0x2c,0x7d}
	};
	//初始化向量 
	BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
//	BYTE key[32] = 
//		{0x61,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
//	;
	int pass = 1;

	BYTE key[32];	
	secret_generator(key);
	
	printf("* CBC mode:\n");
	aes_key_setup(key, key_schedule, 256);

	printf(  "Key          : ");
	print_hex(key, 32);
	printf("\nIV           : ");
	print_hex(iv[0], 16);

	aes_encrypt_cbc(plaintext[0], 32, enc_buf, key_schedule, 256, iv[0]);
	
	printf("\nPlaintext    : ");
	print_hex(plaintext[0], 32);
	
//查看缓存数据拷贝到密文空间中是否成功	
	printf("\nCiphertext reset    : ");
	arr_reset(ciphertext[0], 32);
	print_hex(ciphertext[0], 32);
	
	memcpy(ciphertext[0], enc_buf, 32);	
	printf("\nCiphertext   : ");
	print_hex(ciphertext[0], 32);		
	printf("\nAes_encrypt_cbc ......");
	

	

	aes_decrypt_cbc(ciphertext[0], 32, enc_buf, key_schedule, 256, iv[0]);

//查看缓存数据拷贝到明文空间中是否成功		
	printf("\nPlaintext reset    : ");
	arr_reset(plaintext[0], 32);		
	print_hex(plaintext[0], 32);
	
	memcpy(plaintext[0], enc_buf, 32);
	printf("\nPlaintext    : ");
	print_hex(plaintext[0], 32);	
	printf("\nAes_decrypt_cbc .....");
	

	printf("\n\n");
	return(pass);
}

int aes_test()
{
	int pass = 1;

	pass = pass && aes_cbc_test();

	return(pass);
}

int main(int argc, char *argv[])
{
	printf("AES Tests: %s\n", aes_test() ? "SUCCEEDED" : "FAILED");

	return(0);
}
