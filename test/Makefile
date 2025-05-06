crypt_gensalt_yescrypt.o: crypt_gensalt_yescrypt.c
	gcc -lcrypt crypt_gensalt_yescrypt.c -o crypt_gensalt_yescrypt
crypt_gensalt_scrypt.o: crypt_gensalt_scrypt.c
	gcc -lcrypt crypt_gensalt_scrypt.c -o crypt_gensalt_scrypt

all: crypt_gensalt_scrypt.o crypt_gensalt_yescrypt.o
