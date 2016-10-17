/*********************************************************************
* Filename:   key_gen.c
* Author:     xiongxx
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding generating key for AES implementation.
*********************************************************************/
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include "key_gen.h" 

// calc a * b % p , avoid 64bit overflow
static inline uint64_t
mul_mod_p(uint64_t a, uint64_t b) {
	uint64_t m = 0;
	while(b) {
		if(b&1) {
			uint64_t t = P-a;
			if ( m >= t) {
				m -= t;
			} else {
				m += a;
			}
		}
		if (a >= P - a) {
			a = a * 2 - P;
		} else {
			a = a * 2;
		}
		b>>=1;
	}
	return m;
}

static inline uint64_t
pow_mod_p(uint64_t a, uint64_t b) {
	if (b==1) {
		return a;
	}
	uint64_t t = pow_mod_p(a, b>>1);
	t = mul_mod_p(t,t);
	if (b % 2) {
		t = mul_mod_p(t, a);
	}
	return t;
}

// calc a^b % p
uint64_t
powmodp(uint64_t a, uint64_t b) {
	if (a > P)
		a%=P;
	return pow_mod_p(a,b);
}

uint64_t
randomint64() {
	uint64_t a = rand();
	uint64_t b = rand();
	uint64_t c = rand();
	uint64_t d = rand();
	return a << 48 | b << 32 | c << 16 | d;
}

uint64_t
secret_64_bit() {
	uint64_t a = randomint64(); //����A˽Կ 
	uint64_t b = randomint64(); 
	uint64_t A = powmodp(G, a); //����A��Կ 
	uint64_t B = powmodp(G, b);
	uint64_t secret1 = powmodp(B,a);  //����A���û���B�Ĺ�Կ���ɵĵĹ�����Կ 
	uint64_t secret2 = powmodp(A,b);
	assert(secret1 == secret2);	
	return secret1;
}


char* IntToStr(uint64_t num,char* str)  
{  
    int i = 0, j = 0;  
    char temp[100];	
    while(num)  
    {  
    	int yu = num % 16;
    	if(yu >= 0 && yu <= 9)
    	{
    		temp[i] = yu + '0';   //ȡģ����õ��Ӻ���ǰ��ÿһ�����ֱ���ַ�  
		}
		else
		{
			temp[i] = (yu - 10 )+ 'a';
		}
        
        num = num / 16;  
        i++;  
    }  
    temp[i] = 0;    //�ַ���������־  
      
    i = i - 1;     //�ص�temp���һ�������������  
    while(i >= 0)  
    {  
        str[j] = temp[i];  
        i--;  
        j++;  
    }  
    str[j] = 0;   //�ַ���������־  
    return str ;  
}  



BYTE*
secret_generator(BYTE* key_arr) {
	char *str_a, key_string[60]={0};	
	//BYTE key_arr[4*8];	
	char str_tmp[100]; 
	srand( time(NULL) );  //����ʱ�� ���������������   ���������䣬�����ɵ��ǹ̶�����Կ 
	
	uint64_t str_b;	
		
	int i,j;	
	for(i=0;i<4;i++){	
					
		str_a = IntToStr(str_b=secret_64_bit(),str_tmp); //��Ӧÿ4λת����һ��16�����ַ� �����Ϊ16���ַ� 
		printf("%s\n", str_a);  //printf("%I64x\n",str_a); //��ʾ����8��16���ƣ���Ϊ16���ַ� (0-f)		
				
		for(j=0;j<8;j++){
			key_arr[i*8+j] =(BYTE) (str_b & 0x00ff);
//			printf("%x, ", key_arr[i*8+j]);
			str_b = str_b >> 8;			
		}
		key_arr[33] = 0;
		printf("\n");
				
//		itoa(a[i],str[i],16);//64λ����ת�����ַ������ַ����������˸��ַ���һ���ַ��˸��ֽ� 
//		printf("%s\n",str[i]);

		strcat(key_string,str_a);
		
	}
	
	print_hex(key_arr, 32);

	printf("\n");
	printf("%s\n",key_string);
	
	return key_arr;
}

void 
print_hex(BYTE str[], int len)
{
	int idx;

	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
}


