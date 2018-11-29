#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "gost.h"

unsigned char buffer[MAX_BUFFER_LENGTH];

int load_data_buffer(FILE* input_file) {
    int bytes_read = 0;

    if (feof(input_file)) {
        return bytes_read;
    }
    bytes_read = fread(buffer, 1, MAX_BUFFER_LENGTH, input_file);

	return bytes_read;
}

int main(void) {
	word32 key[8];
	word32 iv[2];
	word32* cipher;
	int i, j;
    int bytes_read;
    int length;
    FILE* in_file;

    long double clock_counter;

	kboxinit();

    in_file = fopen("test_file.txt", "rb");

	printf("GOST 21847-89 test driver.\n");

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
    for (j = 0; j < 8; j++)
        key[j] = RAND32;
    iv[0] = RAND32;
    iv[1] = RAND32;

    clock_counter = clock();

    gostcfbencrypt((word32*)buffer, cipher, length, iv, key);
    gostcfbdecrypt(cipher, (word32*)buffer, length, iv, key);

    clock_counter = ((long double)clock() - clock_counter) / CLOCKS_PER_SEC;

    printf("Data processed in %Lf seconds\n", clock_counter);

    fclose(in_file);

	return 0;
}
