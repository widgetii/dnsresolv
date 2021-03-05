CFLAGS=-O1 -g -fsanitize=address -fno-omit-frame-pointer

dns: dns.o tools.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-rm *.o dns
