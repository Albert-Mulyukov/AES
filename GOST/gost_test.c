#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "gost.h"

#define N_TESTS 10

#define FILE_NAME "test.txt"
#define N_BYTES 10*1024*1024
#define N_BYTES_STEP 10*1024*1024

unsigned char buffer[MAX_BUFFER_LENGTH];

int main(void) {
	word32 key[8];
	word32 iv[2];
	word32* cipher;
	int i, j;
    int bytes_read;
    int length;
    long double clock_counter;
    long double time_total = 0;
    FILE* in_file;
    FILE* res_file;


	printf("GOST 21847-89 test driver.\n");

	kboxinit();

    for (j = 0; j < 8; j++)
        key[j] = RAND32;
    iv[0] = RAND32;
    iv[1] = RAND32;

    create_file(in_file, FILE_NAME, N_BYTES);
    res_file = fopen("result.txt", "w");

    for (i = 0; i < N_TESTS; i++) {
        fprintf(res_file, "%d\t\t", i+1);
    } 
    fprintf(res_file, "\n");

    for (i = 0; i < N_TESTS; i++) {
        in_file = fopen(FILE_NAME, "rb");

        bytes_read = load_data_buffer(in_file);
        fflush(stdout);

        length = bytes_read/8;
        if (bytes_read % 8 != 0) {
            length++;
            memset(buffer + bytes_read,
                    (length*8 - bytes_read),
                    (length*8 - bytes_read));
        }

        cipher = (word32*)malloc(bytes_read * sizeof(word32));

        clock_counter = clock();

        gostcfbencrypt((word32*)buffer, cipher, length, iv, key);
        gostcfbdecrypt(cipher, (word32*)buffer, length, iv, key);
        
        clock_counter = ((long double)clock() - clock_counter) / CLOCKS_PER_SEC;

        time_total += clock_counter;

        printf("Data processed in %Lf seconds\n", clock_counter);

        fprintf(res_file, "%Lf\t", clock_counter);

        free(cipher);
        fclose(in_file);

        increase_file(in_file, FILE_NAME, N_BYTES_STEP);
    } 

    fprintf(res_file, "\ntotal time: %Lf sec", time_total);

    fclose(res_file);

	return 0;
}

int load_data_buffer(FILE* input_file) {
    int bytes_read = 0;

    if (feof(input_file)) {
        return bytes_read;
    }
    bytes_read = fread(buffer, 1, MAX_BUFFER_LENGTH, input_file);

	return bytes_read;
}

void create_file(FILE* file, char* file_name, long int n_bytes) {
    int i;

    file = fopen(file_name, "w");

    for (i = 0; i < n_bytes; i++) {
        fprintf(file, "a");
    }

    fclose(file);
}

void increase_file(FILE* file, char* file_name, long int n_bytes) { 
    int i;

    file = fopen(file_name, "a");

    for (i = 0; i < n_bytes; i++) {
        fprintf(file, "a");
    }

    fclose(file);
}
