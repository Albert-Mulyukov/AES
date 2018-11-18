#include <new>
#include <stdexcept>
#include <cstring>//for memset
#include <iostream>
#include <time.h>


#include "ntstatus.h"
#include "AES_ECB.h"

#define Pause() system("PAUSE");

// Definitions the cypher operations
#define DECRYPT 1
#define ENCRYPT 0
// AES State matrix size definition
#define STATE_SIZE 16
// Number of max STATE matrix hold on memory
#define NUM_STATE_BUFFER 33553920
// So define the data buffer length as the max number of matrix times its size
#define MAX_BUFFER_LENGTH STATE_SIZE*NUM_STATE_BUFFER

unsigned char Buffer[MAX_BUFFER_LENGTH];


#define KEY_SIZE 128


AES_ECB::AES_ECB():m_pbExpDecKey(nullptr), m_pbExpEncKey(nullptr),m_szbKey(NULL),m_pfuncDecBlock(nullptr),m_pfuncEncBlock(nullptr),m_pfuncExpKey(nullptr)
{
	
}
AES_ECB::~AES_ECB()
{
	if(destroyKey())
	{
		//throw expection
	}
}
AES_ECB::AES_ECB(const unsigned char *pbKey, const size_t &szbKey):m_pbExpDecKey(nullptr), m_pbExpEncKey(nullptr),m_szbKey(NULL),m_pfuncDecBlock(nullptr),m_pfuncEncBlock(nullptr),m_pfuncExpKey(nullptr)
{
	if(setKey(pbKey,szbKey));//throw exception
}
unsigned int AES_ECB::destroyKey()
{
	if(m_pbExpEncKey && m_pbExpDecKey && m_szbKey)
	{
		switch(m_szbKey)
		{
		case(16):
			::memset(m_pbExpEncKey,0,11*16);
			::memset(m_pbExpDecKey,0,11*16);
			break;
		case(24):
		case(32):
		default:
			//RETURN expection
			break;
		}
		delete[] m_pbExpEncKey;
		delete[] m_pbExpDecKey;
	}
	m_szbKey=0;
	m_pfuncDecBlock=nullptr;
	m_pfuncEncBlock=nullptr;
	m_pfuncExpKey=nullptr;
	m_pbExpEncKey=nullptr;
	m_pbExpDecKey=nullptr;
	return 0;
}
unsigned int AES_ECB::setKey(const unsigned char *pbKey, const size_t &szbKey)
{
	
	if(this->destroyKey()){return 1;/*throw exception*/}
	switch(szbKey)
	{
	case(16):
		{
			//if 128 bit AES
		m_pbExpEncKey = new (std::nothrow) unsigned char[11*16];
		m_pbExpDecKey = new (std::nothrow) unsigned char[11*16];
		m_szbKey=szbKey;
	
		//Set functions
		m_pfuncExpKey=&AES_ECB::expKey128;
		m_pfuncDecBlock=&AES_ECB::decryptBlock128;
		m_pfuncEncBlock=&AES_ECB::encryptBlock128;
			break;
		}
	case(24):
		{
			//if 192 bit AES
		m_pbExpEncKey = new (std::nothrow) unsigned char[13*16];
		m_pbExpDecKey = new (std::nothrow) unsigned char[13*16];
		m_szbKey=szbKey;
			
		//Set functions
		m_pfuncExpKey=&AES_ECB::expKey192;
		m_pfuncDecBlock=&AES_ECB::decryptBlock192;
		 m_pfuncEncBlock=&AES_ECB::encryptBlock192;
		break;
		}
	case(32):
		{
			break;
		}
	default:
		return 1;//return exception!!!
		break;
	}
	if(!m_pbExpDecKey && !m_pbExpEncKey)
	{//no memmory
		m_szbKey=0;
		return 1;//return exception!!!
	}
	if((this->*m_pfuncExpKey)(pbKey))
	{
		m_szbKey=0;
		return 1;//return exception(can exp key)!!!
	}
	return 0;
}
unsigned int AES_ECB::expKey128(const unsigned char *pbKey)
{
	if(m_szbKey!=16)
	{
		return 1;
	}
	__asm{
		mov ebx, pbKey;
		movups xmm1,[ebx];
		movups xmm4,xmm1;

		mov eax,[this] ;
       	mov ebx,[eax+m_pbExpDecKey];
		add ebx,160;		
		mov eax,[eax+m_pbExpEncKey];
		
		movups [eax], xmm1;                  ;cipher Key
		add eax,0x00000010;
		movups [ebx], xmm1;
		sub ebx,0x00000010;

		aeskeygenassist xmm2, xmm1, 0x1     ;  1 
		call L_key_expansion_128;
		
		aeskeygenassist xmm2, xmm1, 0x2     ;  2 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x4     ;  3 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x8     ;  4 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x10     ;  5 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x20     ; 6 
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x40     // 7
		call L_key_expansion_128;
		
		aeskeygenassist xmm2, xmm1, 0x80     // 8
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x1b;	  //9
		call L_key_expansion_128; 
		
		aeskeygenassist xmm2, xmm1, 0x36;     //  10 
		call L_key_expansion_128; 
		add ebx,0x00000010;
		movups [ebx], xmm1;
		
		jmp end;
L_key_expansion_128: 
	   
	   pshufd xmm2, xmm2, 0xff;
	   movups xmm3, xmm1;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x00;

	   pshufd xmm3, xmm3, 0x39;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x14;

	   pshufd xmm3, xmm3, 0x38;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0xA4;

	   pshufd xmm3, xmm3, 0x34;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   movups [eax], xmm2;
	   movups xmm1, xmm2;
	   add eax,0x00000010;
	   
	   aesimc xmm3, xmm1;
	   movups [ebx], xmm3;
	   sub ebx,0x00000010;	   
	   ret ;
end:
	}
	return 0;
}
unsigned int AES_ECB::expKey192(const unsigned char *pbKey)
{
	if(m_szbKey!=24)
	{
		return 1;
	}
	__asm{
		mov edx, pbKey;
		movups xmm1,[edx];
		
		mov eax,[this] ;
       	mov eax,[eax+m_pbExpEncKey];
		//lea eax,k;


		movups [eax], xmm1;                  ;cipher Key
		movups xmm4, xmm1;

		add eax,0x00000008;
		add edx,0x00000008;
		
		movups xmm1,[edx];
		movups [eax], xmm1;
		add eax,0x00000010;

		
		aeskeygenassist xmm2, xmm1, 0x1     ;  1 
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x2     ;  2 
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x4     ;  3
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x8     ;  4
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x10     ;  5
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x20     ;  6
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x40     ;  7
		call L_key_expansion_192;

		aeskeygenassist xmm2, xmm1, 0x80     ;  8
		call L_key_expansion_192_last;

		call L_key_expansion_192_for_decrypt;


		jmp end;
	
L_key_expansion_192:

	   pshufd xmm2, xmm2, 0xff; 
	   movups xmm3, xmm4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x00;
	  

	   pshufd xmm3, xmm3, 0x39;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x14;

	   pshufd xmm3, xmm3, 0x38;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0xA4;

	   pshufd xmm3, xmm3, 0x34;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   movups [eax], xmm2;
	   add eax,0x00000010;

	   pshufd xmm2, xmm2, 0xff;
	   pshufd xmm1, xmm1, 0xfe;
	   pxor xmm2,xmm1;

	   pshufd xmm2, xmm2, 0x00;
	   pslldq xmm1,0x4;
	   pshufd xmm1, xmm1, 0x08;
	   pxor xmm2,xmm1;

	   movups [eax], xmm2;
	   add eax,0x00000008;
	   movups xmm1,[eax-16];
	   movups xmm4,[eax-24];

	   ret;
L_key_expansion_192_last:

	   pshufd xmm2, xmm2, 0xff; 
	   movups xmm3, xmm4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x00;
	  

	   pshufd xmm3, xmm3, 0x39;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0x14;

	   pshufd xmm3, xmm3, 0x38;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   pshufd xmm2, xmm2, 0xA4;

	   pshufd xmm3, xmm3, 0x34;
	   pslldq xmm3,0x4;
	   pxor xmm2,xmm3;
	   movups [eax], xmm2;
	   ret;
L_key_expansion_192_for_decrypt:
	   	mov eax,[this] ;
       	mov ebx,[eax+m_pbExpDecKey];
		add ebx,192;
		mov eax,[eax+m_pbExpEncKey];

		movups xmm1,[eax];
		movups [ebx],xmm1;

		add eax,16;                  //1
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //2
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //3
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //4
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //5
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //6
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //7
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //8
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //9
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //10
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //11
		sub ebx,16;

		movups xmm1,[eax];
		aesimc xmm1, xmm1;
		movups [ebx],xmm1;

		add eax,16;                  //12
		sub ebx,16;

		movups xmm1,[eax];
		//aesimc xmm1, xmm1;
		movups [ebx],xmm1;
		ret;

		
end:
		}
		return 0;
	
}

unsigned int AES_ECB::encryptBlock128(const unsigned char *pbInput,unsigned char *pbOutput)
{
	if(!m_pbExpEncKey){return 1;/*exception*/}
	__asm
	{
		mov ebx,pbInput;
		movups xmm1,[ebx];

		mov eax,[this] ;
		mov eax,[eax+m_pbExpEncKey];
		movups xmm2,[eax];

		pxor xmm1,xmm2;
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 1 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 2 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 3 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 4 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 5
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 6 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 7 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 8 
		add eax,0x00000010;
		movups xmm2,[eax];
		aesenc xmm1, xmm2 ; Round 9
        add eax,0x00000010;
		movups xmm2,[eax];
		aesenclast xmm1, xmm2 ; Round 10 
		mov ebx,pbOutput;
		movups [ebx],xmm1;
}
	return 0;
}
unsigned int AES_ECB::encryptBlock192(const unsigned char *pbInput,unsigned char *pbOutput)
{

	if(!m_pbExpEncKey){return 1;/*exception*/}
	__asm
	{
		mov ebx,pbInput;
		movups xmm1,[ebx];

		mov eax,[this] ;
		mov eax,[eax+m_pbExpEncKey];
		movups xmm2,[eax];

		pxor xmm1,xmm2;
		add eax,0x00000010;
		movups xmm2,[eax];
		
		aesenc xmm1, xmm2 ; Round 1 
		add eax,0x00000010;
		movups xmm2,[eax];
		

		aesenc xmm1, xmm2 ; Round 2 
		add eax,0x00000010;
		movups xmm2,[eax];
		
		aesenc xmm1, xmm2 ; Round 3 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 4 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 5
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 6 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 7 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 8 
		add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 9
        add eax,0x00000010;
		movups xmm2,[eax];

		
		aesenc xmm1, xmm2 ; Round 10 
	    add eax,0x00000010;
		movups xmm2,[eax];


		aesenc xmm1, xmm2 ; Round 11 
	    add eax,0x00000010;
		movups xmm2,[eax];
		
		
		aesenclast xmm1, xmm2 ; Round 12 
	    add eax,0x00000010;
	
		mov ebx,pbOutput;
		movups [ebx],xmm1;
}
	return 0;
}
unsigned int AES_ECB::encrypt(const unsigned char *pbInput, const size_t szbInput, unsigned char *pbOutput, const size_t szbOutput, size_t *szbResult)
{
	if(!m_szbKey){ return 1;/*exception*/}
	unsigned char bPadBlock[16];
	unsigned int iPadind=16-(szbInput%16);
	size_t cBlock=szbInput/16;
	*szbResult=0;
	if((szbResult && !szbOutput))*szbResult=(cBlock+(iPadind/16))*16;//если запршивается тьребуемый размер
	
	if(!szbOutput)return 0;//если запршивается тьребуемый размер

	if(szbOutput<((iPadind/16)+cBlock)*16)//если нету памяти для расшифровки
	{
		*szbResult=0;
		return 1;
	}

	for(unsigned int i=0;i<szbInput%16;++i)
	{
		bPadBlock[i]=pbInput[(cBlock*16)+i];
	}
	
	for(unsigned int i=szbInput%16;i<16;++i)
	{
		bPadBlock[i]=iPadind;
	}
	
	for(unsigned int i=0;i<cBlock;++i)
	{
		(this->*m_pfuncEncBlock)(pbInput+(i*16),pbOutput+(i*16));
		(*szbResult)+=16;
	}
	(this->*m_pfuncEncBlock)(bPadBlock,pbOutput+(cBlock*16));
	(*szbResult)+=16;
	::memset(bPadBlock,0,16);
	return 0;
}
unsigned int AES_ECB::decrypt(const unsigned char *pbInput, const size_t szbInput, unsigned char *pbOutput, const size_t szbOutput, size_t *szbResult)
{
	*szbResult=0;
	if(!m_szbKey){ return 1;/*exception*/}
	if(szbInput%16)return 1;
	unsigned char bPadBlock[16];
	(this->*m_pfuncDecBlock)(pbInput+(((szbInput/16)-1)*16),bPadBlock);
	if(bPadBlock[15]>16){return 1;::memset(bPadBlock,0,16);}
	if(szbResult && !szbOutput) *szbResult=szbInput-bPadBlock[15];
	
	if(szbOutput<szbInput-bPadBlock[15]){return 1;::memset(bPadBlock,0,16);}

	for(unsigned int i=0; i< (szbInput/16)-1;++i)
	{
		(this->*m_pfuncDecBlock)(pbInput+(i*16),pbOutput+(i*16));
		(*szbResult)+=16;
	}
	for(unsigned int i=0;i<16-bPadBlock[15];++i)
	{
		*(pbOutput+(((szbInput/16)-1)*16)+i)=bPadBlock[i];
		(*szbResult)++;
	}
	::memset(bPadBlock,0,16);
	return 0;
}
unsigned int AES_ECB::decryptBlock128(const unsigned char *pbInput,unsigned char *pbOutput)
{
	__asm{
		mov eax,[this] ;
		mov eax,[eax+m_pbExpDecKey];
		
		movups xmm2,[eax];

		mov ebx,pbInput;
		movups xmm1,[ebx];
		pxor xmm1, xmm2 ; First xor


		add eax,0x00000010;
		movups xmm2,[eax]; 
		aesdec xmm1, xmm2 ; Round 1 


		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 2 
		

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 3

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 4 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 5

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 6

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 7

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 8 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 9 


		add eax,0x00000010;
		movups xmm2,[eax];
		aesdeclast xmm1, xmm2 ; Round 10 
	    mov ebx,pbOutput;
		movups [ebx],xmm1;

	}
	return 0;
}
unsigned int AES_ECB::decryptBlock192(const unsigned char *pbInput,unsigned char *pbOutput)
{
			unsigned char m[16];
	__asm{
		mov eax,[this] ;
		mov eax,[eax+m_pbExpDecKey];
		
		movups xmm2,[eax];

		mov ebx,pbInput;
		movups xmm1,[ebx];
		pxor xmm1, xmm2 ; First xor

		lea ebx,m;
		movups [ebx],xmm1;


		add eax,0x00000010;
		movups xmm2,[eax]; 
		aesdec xmm1, xmm2 ; Round 1 


		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 2 
		

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 3

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 4 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 5

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 6

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 7

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 8 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 9 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 10 

		add eax,0x00000010;
		movups xmm2,[eax];
		aesdec xmm1, xmm2 ; Round 11 
        
		add eax,0x00000010;
		movups xmm2,[eax];
		aesdeclast xmm1, xmm2 ; Round 12 
	    mov ebx,pbOutput;
//		lea ebx,m;
		movups [ebx],xmm1;

	}
	return 0;
}








int ReadKey(unsigned char Key[], FILE * KeyFile) {
	int key_it = fread(Key, 1, 32, KeyFile);
	fclose(KeyFile);
	return key_it;
}

void EndWithError(FILE* inFile, FILE* outFile, char* oFilename) {
	printf("\nError raised, the program finishes now\n");
	// Close the files, remove the output file and exit
	fclose(inFile);
	fclose(outFile);
	remove(oFilename);
	Pause();
	exit(EXIT_SUCCESS);
}

int LoadDataBuffer(FILE* inputFile) {
	int bytesRead = 0;
	// Check if the entire file has been consumed
	if (feof(inputFile)) {
		return bytesRead;
	}
	// Try to read the buffer size
	bytesRead = fread(Buffer, 1, MAX_BUFFER_LENGTH, inputFile);

	printf("Loading the input file...\r");
	fflush(stdout);

	if (bytesRead > 1024) {
		printf("Buffer loaded (%d KB read)                                 \n", bytesRead / 1024);
	}
	else if (bytesRead > 0) {
		printf("Buffer loaded (%d B read)                                  \n", bytesRead);
	}
	else {
		printf("Buffer not loaded, empty file?                                      \n");
	}

	return bytesRead;
}

int WriteBuffer(unsigned char outBuffer[], int nStatesInBuffer, FILE * outFile, unsigned char inv) {
	int nPaddingBytes = 0, lastByte = (nStatesInBuffer - 1) * 16 + 15, bytesWritten;
	// Get the last byte from the data
	unsigned char byte_padding = outBuffer[lastByte];

	/* Check the last bytes to detect the number of padding bytes on the buffer.
	 * This operation its only done while DECRYPT, and repeated value means its
	 * a padding byte.*/
	for (; inv == DECRYPT && lastByte > 0 && byte_padding == outBuffer[lastByte]; lastByte--) {
		nPaddingBytes++;
	}

	if (nPaddingBytes > 1) printf("Detected %d padding bytes\n", nPaddingBytes);

	printf("Writing data from buffer into the output file...\n");
	fflush(stdout);

	int bytesToWrite = (nPaddingBytes > 1 && nPaddingBytes <= 15) ? nStatesInBuffer * 16 - nPaddingBytes : nStatesInBuffer * 16;
	bytesWritten = fwrite(outBuffer, 1, bytesToWrite, outFile);
	if (bytesWritten > 1024) {
		printf("Bytes written (%d KB)                           \n\n", bytesWritten / 1024);
	}
	else if (bytesWritten > 0) {
		printf("Bytes written (%d B)                           \n\n", bytesWritten);
	}
	else {
		printf("Nothing has been written on the output file  \n\n");
	}
	return bytesWritten;
}

void closeAES(FILE* in, FILE * out) {
	fclose(in);
	fclose(out);
}


int main()
{
	AES_ECB aes;

	/* File names */
	char task;
	char keyFilename[100];
	char inputFilename[100];
	char outputFilename[100];
	printf("encryption (e) or decryption (d) : ");
	scanf("%c", &task);
	printf("Key file name : ");
	scanf("%s", keyFilename);
	printf("Input file name : ");
	scanf("%s", inputFilename);
	printf("Output file name : ");
	scanf("%s", outputFilename);
	//const char keyFilename[4] = "key";
	//const char inputFilename[10] = "video.mp4";
	//const char outputFilename[14] = "video.mp4.cpt";

	/* File pointers */
	FILE *inFile, *outFile, *keyFile = NULL;

	/* Files initialization*/
	printf("\n\nOpening files...\n");
	keyFile = fopen(keyFilename, "rb");
	inFile = fopen(inputFilename, "rb");
	if (keyFile == NULL) {
		printf("Error opening file \"%s\" for key reading \n", keyFilename);
		Pause();
		exit(EXIT_SUCCESS);
	}
	else {
		printf("File \"%s\" opened successfully for key reading\n", keyFilename);
	}
	if (inFile == NULL) {
		printf("Error opening the input file \"%s\"\n", inputFilename);
		Pause();
		exit(EXIT_SUCCESS);
	}
	else {
		printf("Input file \"%s\" opened successfully\n", inputFilename);
	}

	/*Create the output file. If the name given is the same as the input, add a suffix.*/
	if (strcmp(inputFilename, outputFilename) == 0) {
		printf("Output file name must be different, adding suffix\n: \"%s.out\"\n", outputFilename);
		outFile = fopen(outputFilename, "wb");
	}
	else {
		outFile = fopen(outputFilename, "wb");
	}
	if (outFile == NULL) {
		printf("Error creating the output file\n");
		fclose(inFile);
		fclose(keyFile);
		exit(EXIT_SUCCESS);
	}
	else {
		printf("Output file \"%s\" created and opened successfully\n", outputFilename);
	}

	/*Key reading*/
	int expkey_it, klong = 0;
	unsigned char Key[32];
	printf("\nLeyendo la clave...\n");
	klong = ReadKey(Key, keyFile);
	if (klong != KEY_SIZE / 8) {
		printf("Key length expected %d bytes, key length read %d bytes\n", KEY_SIZE / 8, klong);
		EndWithError(inFile, outFile, outputFilename);
	}
	printf("Key read form the file: \n");
	for (expkey_it = 0; expkey_it < KEY_SIZE / 8; expkey_it++) {
		printf("%02x ", Key[expkey_it]);
		if (expkey_it == KEY_SIZE / 8 - 1) printf("\n");
	}
	aes.setKey(Key, 16);


	/* Load from the file and process it*/
	int bytesRead, bytesWritten;
	int hdd_cont = 0;
	unsigned long processedBytes = 0L;
	unsigned long nStatesInBuffer = 0L;
	clock_t clockCounter;
	unsigned long totalTime = 0L;
	while (bytesRead = LoadDataBuffer(inFile)) {
		printf("Processing data from buffer                                   \r");
		fflush(stdout);

		hdd_cont++;

		/* Update the number of state matrix on the buffer*/
		nStatesInBuffer = bytesRead / 16;
		if (bytesRead % 16 != 0) {
			printf("Bytes read is not multiple of 16. %d -> %d\n", bytesRead, bytesRead / 16);
			/* If the number of bytes read is not divisible by 16, insert
			 the rest of the bytes and add padding bytes.*/
			nStatesInBuffer++;
			memset(Buffer + bytesRead, ((nStatesInBuffer * 16) - bytesRead), ((nStatesInBuffer * 16) - bytesRead));
		}

		/* Start timing */
		clockCounter = clock();

		/* Process every state matrix from the buffer */
		unsigned long states_it = 0L;
		unsigned char State[16];
		unsigned char *tmp = (unsigned char *)malloc((bytesRead+16)*sizeof(unsigned char));
		size_t res;
		if (task == 'e')
			aes.encrypt(Buffer, bytesRead, tmp, bytesRead + 16, &res);
		else if (task == 'd')
			aes.decrypt(Buffer, bytesRead, tmp, bytesRead, &res);
		else
			printf("Nothing done, wrong task ( not 'e' or 'd' )\n");
		
		printf("Data processed in %Lf seconds    \n"
			"", ((long double)clock() - clockCounter) / CLOCKS_PER_SEC);

		totalTime += ((unsigned long)clock() - clockCounter) / CLOCKS_PER_SEC;

		// Write the buffer to the output file
		bytesWritten = WriteBuffer(tmp, nStatesInBuffer, outFile, ENCRYPT);
		if (bytesWritten < nStatesInBuffer) {
			printf("Error writing the buffer on the output file!!\n");
			EndWithError(inFile, outFile, outputFilename);
		}

		hdd_cont++;
		free(tmp);

		// Update the number of bytes processed
		processedBytes += bytesRead;
	}

	closeAES(inFile, outFile);
	printf("\n\nPROCESS FINISHED!!\n");
	printf("Processed: %lu bytes \nHDD I/O operations: %d I/Os\n", processedBytes, hdd_cont);
	printf("Time elapsed: %lu seconds (aprox).\n", totalTime);
	Pause();
}