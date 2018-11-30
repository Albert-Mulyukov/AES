all: gost.o gost_test

gost.o:
	gcc -c gost.c -o gost.o -O3

gost_test:
	gcc -o gost_test gost.o gost_test.c -O3

clean:
	rm gost_test gost.o
