CFLAGS=-O1 -g -fsanitize=address -fno-omit-frame-pointer -g

dns: dns.o tools.o http.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-rm *.o dns
