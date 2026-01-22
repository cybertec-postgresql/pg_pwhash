PG_CONFIG ?= pg_config
MODULE_big = pg_pwhash
OBJS = pwhash_yescrypt.o pwhash_argon2.o pwhash_scrypt.o pg_pwhash.o $(WIN32RES)
PGFILEDESC = "pg_pwhash - An implementation for advanced password hashing"

EXTENSION = pg_pwhash
DATA = pg_pwhash--1.0.sql
DOCS = pg_pwhash.md

REGRESS = pg_pwhash argon2 argon2_openssl scrypt scrypt_crypt scrypt_libscrypt yescrypt

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Add libraries that pgxcrypto_pwhash depends (or might depend) on into the
# shared library link.  (The order in which you list them here doesn't
# matter.)
SHLIB_LINK += -lcrypt -lscrypt -lm -lcrypto -lz -largon2
ifeq ($(PORTNAME), win32)
SHLIB_LINK += $(filter -leay32, $(LIBS))
# those must be at the end
SHLIB_LINK += -lws2_32
endif
