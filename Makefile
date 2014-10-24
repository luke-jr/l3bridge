all: l3bridge

CFLAGS = -O0 -ggdb -Wall -Werror
xCFLAGS = $(CFLAGS) -std=gnu99

l3bridge: l3bridge.o util.o
	$(CC) $(xCFLAGS) -o $@ $^

%.o: %.c
	$(CC) -c $(xCFLAGS) -o $@ $^
