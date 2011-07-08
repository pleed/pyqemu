CC      = /usr/bin/gcc
CFLAGS  = -fPIC -O3 -Wall -Werror -D_GNU_SOURCE
LDFLAGS = 
OBJ = aho-corasick.o slist.o shmatch.o acwrap.o
TESTOBJ = test.o $(OBJ)

libshmatch: $(OBJ)
	$(CC) $(CFLAGS) -shared -o libshmatch.so $(OBJ) $(LDFLAGS)

test: $(TESTOBJ)
	$(CC) $(CFLAGS) -o test $(TESTOBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o
	rm -f test
	rm -f libshmatch.so
