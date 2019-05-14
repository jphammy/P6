# Makefile with Suffix Rules

CC = gcc

all: oss ass6

.SUFFIXES: .c .o

oss: oss.c memoryManagement.h
	gcc -g -Wall -lpthread -lrt -lm -o oss oss.c

ass6: ass6.c memoryManagement.h
	gcc -g -Wall -lpthread -lrt -lm -o ass6 ass6.c

clean:
	$(RM) oss ass6 *.txt *.o

