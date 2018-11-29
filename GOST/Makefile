all: gost.o gost_test

gost.o:
	gcc -c gost.c -o gost.o

gost_test:
	gcc -o gost_test gost.o gost_test.c 

clean:
	rm gost_test gost.o
