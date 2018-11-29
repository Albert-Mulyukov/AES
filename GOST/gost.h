#ifndef GOST_H
#define GOST_H

#include <stdlib.h>
#include <stdio.h>

#define NUM_STATE_BUFFER 33553920
#define MAX_BUFFER_LENGTH 64*NUM_STATE_BUFFER

/* Designed to cope with 15-bit rand() implementations */
#define RAND32 ((word32)rand() << 17 ^ (word32)rand() << 9 ^ rand())


/* A 32-bit data type */
#ifdef __alpha  /* Any other 64-bit machines? */
typedef unsigned int word32;
#else
typedef unsigned long word32;
#endif

/* Build byte-at-a-time subtitution tables. */
void kboxinit(void);

/* Do the substitution and rotation that are the core of the operation,
 * like the expansion, substitution and permutation of the DES. */
#if __GNUC__
__inline__
#endif
static word32 f(word32 x);

/* The GOST encryption. */
void gostcrypt(word32 const in[2], word32 out[2], word32 const key[8]);

/* The GOST decryption. */
void gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8]);

/* The GOST "Output feedback" standard. */
void gostofb(word32 const *in, word32 *out, int len,
	word32 const iv[2], word32 const key[8]);

/* The CFB mode. */
void gostcfbencrypt(word32 const *in, word32 *out, int len,
	       word32 iv[2], word32 const key[8]);

void gostcfbdecrypt(word32 const *in, word32 *out, int len,
	       word32 iv[2], word32 const key[8]);

/* The message suthetication code. */
void gostmac(word32 const *in, int len, word32 out[2], word32 const key[8]);

/* Read the data */
int load_data_buffer(FILE* input_file);

#endif /* GOST_H */
