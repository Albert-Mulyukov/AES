

// Flag needed to support files grater than 2GB
#define _FILE_OFFSET_BITS 64

// FIX: Solves Windows warning when opening files with fopen()
#ifdef _WIN32
#define _CRT_SECURE_NO_DEPRECATE
#define Pause() system("PAUSE");
#else
#define fopen fopen64
#define Pause() {}
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Definitions the cypher operations
#define DECRYPT 1
#define ENCRYPT 0
// RC6 State matrix size definition
#define STATE_SIZE 16
// Number of max STATE matrix hold on memory
#define NUM_STATE_BUFFER 33553920
// So define the data buffer length as the max number of matrix times its size
#define MAX_BUFFER_LENGTH STATE_SIZE*NUM_STATE_BUFFER

typedef unsigned char byte;

/**********************
 * GLOBAL DEFINITIONS *
 **********************/

/********************
 * GLOBAL VARIABLES *
 ********************/
// Key size
int KEY_SIZE;
// The cypher operation (ENCRYPT o DECRYPT)
int CYPHER_OP;
// The data buffer which stores the data to process
byte Buffer[MAX_BUFFER_LENGTH];

// Key array
byte Key[32];
// State matrix which will store the data on each RC6 round
unsigned int State[4];
unsigned int Output[4];

/*********************
 * UTILITY FUNCTIONS *
 *********************/

/**
 * Prints a State matrix to the terminal.
 * 
 * @param state The state matrix to print.
 */


/**
 * Read a file and stores the data into the data buffer.
 * @param inFile The file to read (already opened).
 * @return  The number of bytes read
 */
int LoadDataBuffer(FILE* inputFile) {
    int bytesRead = 0;
    // Check if the entire file has been consumed
    if(feof(inputFile)) {
    return bytesRead;
    }
    // Try to read the buffer size
    bytesRead = fread(Buffer, 1, MAX_BUFFER_LENGTH, inputFile);

    printf("Loading the input file...\r");
    fflush(stdout);

    if (bytesRead > 1024 ) {
        printf("Buffer loaded (%d KB read)                                 \n", bytesRead / 1024);
    } else if (bytesRead > 0) {
        printf("Buffer loaded (%d B read)                                  \n", bytesRead);
    } else {
        printf("Buffer not loaded, empty file?                                      \n");
    }

    return bytesRead;
}

/**
 * Read a file and stores the data into the data buffer.
 * @param outBuffer The buffer to write
 * @param nStatesInBuffer The amount of state matrix inside the buffer
 * @param outFile File pointer to the output file
 * @param inv Operation code
 * @return  The number of bytes written
 */
int WriteBuffer(byte outBuffer[], int nStatesInBuffer, FILE * outFile, byte inv) {
    int nPaddingBytes = 0, lastByte = (nStatesInBuffer - 1)*16 + 15, bytesWritten;
    // Get the last byte from the data
    byte byte_padding = outBuffer[lastByte];

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
    } else if (bytesWritten > 0) {
        printf("Bytes written (%d B)                           \n\n", bytesWritten);
    } else {
        printf("Nothing has been written on the output file  \n\n");
    }
    return bytesWritten;
}

/**
 * Read the key from the file.
 * @param Key Array to store the key.
 * @param KeyFile The file where the key is stored.
 * @return The key length
 */
int ReadKey(byte Key[], FILE * KeyFile) {
    int key_it = fread(Key, 1, 32, KeyFile);
    fclose(KeyFile);
    return key_it;
}

/**
 * Prints an error and exits.
 * @param inFile The file to process.
 * @param outFile The output file
 * @param oFilename The output filename
 */
void EndWithError(FILE* inFile, FILE* outFile, char* oFilename) {
    printf("\nError raised, the program finishes now\n");
    // Close the files, remove the output file and exit
    fclose(inFile);
    fclose(outFile);
    remove(oFilename);
    Pause();
    exit(EXIT_SUCCESS);
}

/**
 * Key expansion function. Implements: https://en.wikipedia.org/wiki/Rijndael_key_schedule
 * 
 * @param Key The key buffer array.
 */

/**
 * RC6 initialization function.
 * @param op The operation character the user introduced on the program execution command. 'e' for encrypt and 'd' for decrypt.
 * @param KeyLong The key length. 1 for 128 bits, 2 for 192 bits and 3 for 256 bits
 * @param inputFile The file to get the data from.
 * @param outputFile The file to put the processed data on.
 * @param keyFile The file with the key value.
 * @param inputFilename The filename of the input file.
 * @param outputFilename The filename of the output file.
 * @param keyFilename The filename of the key file.
 */





////////////////////////////////////////   
#define w 32/* word size in bits */
#define r 20/* based on security estimates */
#define P32 0xB7E15163/* Magic constants for key setup */
#define Q32 0x9E3779B9
/* derived constants */
#define bytes (w / 8)/* bytes per word */
#define c ((b + bytes - 1) / bytes)/* key in words, rounded up */
#define R24 (2 * r + 4)
#define lgw 5/* log2(w) -- wussed out */
/* Rotations */
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
unsigned int S[R24 - 1]; /* Key schedule */
void rc6_key_setup(unsigned char *K, int b)
{
int i, j, s, v;
unsigned int L[(32 + bytes - 1) / bytes]; /* Big enough for max b */
unsigned int A, B;

L[c - 1] = 0;
for (i = b - 1; i >= 0; i--)
L[i / bytes] = (L[i / bytes] << 8) + K[i];

S[0] = P32;
for (i = 1; i <= 2 * r + 3; i++)
S[i] = S[i - 1] + Q32;

A = B = i = j = 0;
v = R24;
if (c > v) v = c;
v *= 3;

for (s = 1; s <= v; s++)
{
A = S[i] = ROTL(S[i] + A + B, 3);
B = L[j] = ROTL(L[j] + A + B, A + B);
i = (i + 1) % R24;
j = (j + 1) % c;
}
}

void rc6_block_encrypt(unsigned int *pt, unsigned int *ct)
{
unsigned int A, B, C, D, t, u, x;
int i, j;

A = pt[0];
B = pt[1];
C = pt[2];
D = pt[3];
B += S[0];
D += S[1];
for (i = 2; i <= 2 * r; i += 2)
{
t = ROTL(B * (2 * B + 1), lgw);
u = ROTL(D * (2 * D + 1), lgw);
A = ROTL(A ^ t, u) + S[i];
C = ROTL(C ^ u, t) + S[i + 1];
x = A;
A = B;
B = C;
C = D;
D = x;
}
A += S[2 * r + 2];
C += S[2 * r + 3];
ct[0] = A;
ct[1] = B;
ct[2] = C;
ct[3] = D;
}

void rc6_block_decrypt(unsigned int *ct, unsigned int *pt)
{
unsigned int A, B, C, D, t, u, x;
int i, j;

A = ct[0];
B = ct[1];
C = ct[2];
D = ct[3];
C -= S[2 * r + 3];
A -= S[2 * r + 2];
for (i = 2 * r; i >= 2; i -= 2)
{
x = D;
D = C;
C = B;
B = A;
A = x;
u = ROTL(D * (2 * D + 1), lgw);
t = ROTL(B * (2 * B + 1), lgw);
C = ROTR(C - S[i + 1], t) ^ u;
A = ROTR(A - S[i], u) ^ t;
}
D -= S[1];
B -= S[0];
pt[0] = A;
pt[1] = B;
pt[2] = C;
pt[3] = D;
}

/////////////////////////////////////







void initRC6(char* op, char* KeyLong, FILE** inputFile,
        FILE** outputFile, FILE* keyFile, char* inputFilename,
        char* outputFilename, char* keyFilename) {

    int expkey_it, klong = 0;

    /* Check the operation value */
    if (*op != 'd' && *op != 'e') {
        printf("Unknown operation\n");
        Pause();
        exit(EXIT_SUCCESS);
    } else {
        /* If the value is correct, set the operation */
        CYPHER_OP = (*op == 'd');
    }

    /* From the key length value (128, 192 or 256 bits) set the values for
     * the expanded key length and the necessary RC6 rounds. */
    if (*KeyLong == '1') {
        KEY_SIZE = 128;
    } else if (*KeyLong == '2') {
        KEY_SIZE = 192;
    } else if (*KeyLong == '3') {
        KEY_SIZE = 256;
    } else {
        printf("Key length unknown \n");
        Pause();
        exit(EXIT_SUCCESS);
    }

    /* Files initialization*/
    printf("\nOpening files...\n");
    keyFile = fopen(keyFilename, "rb");
    *inputFile = fopen(inputFilename, "rb");
    if (keyFile == NULL) {
        printf("Error opening file \"%s\" for key reading \n", keyFilename);
        Pause();
        exit(EXIT_SUCCESS);
    } else {
        printf("File \"%s\" opened successfully for key reading\n", keyFilename);
    }
    if (*inputFile == NULL) {
        printf("Error opening the input file \"%s\"\n", inputFilename);
        Pause();
        exit(EXIT_SUCCESS);
    } else {
        printf("Input file \"%s\" opened successfully\n", inputFilename);
    }

    /*Create the output file. If the name given is the same as the input, add a suffix.*/
    if (strcmp(inputFilename, outputFilename) == 0) {
        printf("Output file name must be different, adding suffix\n: \"%s.out\"\n", outputFilename);
        *outputFile = fopen(strcat(outputFilename, ".out"), "wb");
    } else {
        *outputFile = fopen(outputFilename, "wb");
    }
    if (outputFile == NULL) {
        printf("Error creating the output file\n");
        fclose(*inputFile);
        fclose(keyFile);
        exit(EXIT_SUCCESS);
    } else {
        printf("Output file \"%s\" created and opened successfully\n", outputFilename);
    }
    /*Key reading*/
    printf("\nLeyendo la clave...\n");
    klong = ReadKey(Key, keyFile);
    if (klong != KEY_SIZE / 8) {
        printf("Key length expected %d bytes, key length read %d bytes\n", KEY_SIZE / 8, klong);
        EndWithError(*inputFile, *outputFile, outputFilename);
    }
    printf("Key read form the file: \n");
    for (expkey_it = 0; expkey_it < KEY_SIZE / 8; expkey_it++) {
        printf("%02x ", Key[expkey_it]);
        if (expkey_it == KEY_SIZE / 8 - 1) printf("\n");
    }

    /*Key expansion*/
    printf("\nExpanding key...\n");
    rc6_key_setup(Key, KEY_SIZE/8);

    printf("RC6 initialized successfully\n\n");
}

void closeRC6(FILE* in, FILE * out) {
    fclose(in);
    fclose(out);
}












int main(int argc, char** argv) {

    /* Iterators */
    int bytesRead, bytesWritten;
    unsigned long states_it = 0L;

    /* Number of state matrix stored on the buffer*/
    unsigned long nStatesInBuffer = 0L;

    /* Counters for metrics */
    int hdd_cont = 0;
    unsigned long processedBytes=  0L;

    /* File pointers */
    FILE *inFile, *outFile, *keyFile = NULL;

    /* Clock variables to show the time elapsed */
    clock_t clockCounter;
    clock_t totalClockCounter;
    long double totalProcessedTime = 0;
    long double processedTime;
    long double totalTime;

    if (argc == 6) {
        initRC6(argv[1], argv[2], &inFile, &outFile, keyFile, argv[3], argv[4], argv[5]);

        totalClockCounter = clock();

        /* Load from the file and process it*/
        while (bytesRead = LoadDataBuffer(inFile)) {
            printf("Processing data from buffer                                   \r");
            fflush(stdout);

            hdd_cont++;

            /* Update the number of state matrix on the buffer*/
            nStatesInBuffer = bytesRead / 16;
            if (bytesRead % 16 != 0) {
        printf("Bytes read is not multiple of 16. %d -> %d\n", bytesRead, bytesRead/16);
                /* If the number of bytes read is not divisible by 16, insert
                 the rest of the bytes and add padding bytes.*/
                nStatesInBuffer++;
                memset(Buffer + bytesRead, ((nStatesInBuffer * 16) - bytesRead), ((nStatesInBuffer * 16) - bytesRead));
            }

            /* Start process timing */
            clockCounter = clock();

            /* Process every state matrix from the buffer */
            for (states_it = 0; states_it < nStatesInBuffer; states_it++) {
                // Init current state matrix
                memcpy(State, Buffer + states_it * 16, 16);

                // RC6 execution
                if(CYPHER_OP == 0)
                    rc6_block_encrypt(State, Output);
                else
                    rc6_block_decrypt(State, Output);

                // Replace the original data on the buffer with the result.
                memcpy(Buffer + states_it * 16, Output, 16);
                if (states_it % 5000 == 0) {
                    printf("Processed %lu%% from the buffer       \r", (states_it + 1) *100 / nStatesInBuffer);
                }
            }
            processedTime = ((long double) clock() - clockCounter) / CLOCKS_PER_SEC;
            printf("Data processed in %Lf seconds    \n"
                    "", processedTime);

            totalProcessedTime += processedTime;

            // Write the buffer to the output file
            bytesWritten = WriteBuffer(Buffer, nStatesInBuffer, outFile, (*argv[1] == 'd') ? DECRYPT : ENCRYPT);
            if (bytesWritten < nStatesInBuffer) {
                printf("Error writing the buffer on the output file!!\n");
                EndWithError(inFile, outFile, argv[4]);
            }

            hdd_cont++;

            // Update the number of bytes processed
            processedBytes += bytesRead;
        }

        totalTime = ((long double)clock() - totalClockCounter) / CLOCKS_PER_SEC;

        closeRC6(inFile, outFile);
        printf("\n\nPROCESS FINISHED!!\n");
        printf("Processed: %lu bytes \nHDD I/O operations: %d I/Os\n", processedBytes, hdd_cont);
        printf("Time elapsed : %lu seconds (aprox).\n", (unsigned long)totalProcessedTime);
        printf("Total time   : %lu seconds (aprox).\n", (unsigned long)totalTime);
        printf("\nProcessing speed : %LF MB/s\n", processedBytes / totalProcessedTime / 1000000);
        printf("Real speed       : %LF MB/s\n", processedBytes / totalTime / 1000000);
        Pause();
        return (EXIT_SUCCESS);
    } else {
        printf("Execution command: '$>./RC6 <operation> <key_length> <input_file> <output_file> <key_file>'\n");
        Pause();
    } 
}