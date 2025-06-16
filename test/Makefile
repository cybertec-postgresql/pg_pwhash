CC ?= cc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcrypt

TARGETS = crypt_gensalt_yescrypt crypt_gensalt_scrypt

all: $(TARGETS)

crypt_gensalt_yescrypt: crypt_gensalt_yescrypt.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

crypt_gensalt_scrypt: crypt_gensalt_scrypt.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
