PG_CONFIG ?= pg_config
MODULE_big = pgxcrypto_pwhash
OBJS = pgxcrypto_yescrypt.o pgxcrypto_argon2.o pgxcrypto_scrypt.o pgxcrypto_pwhash.o $(WIN32RES)
PGFILEDESC = "pgxcrypto_pwhash - An implementation for advanced password hashing"

EXTENSION = pgxcrypto_pwhash
DATA = pgxcrypto_pwhash--1.0.sql
DOCS = pgxcrypto_pwhash.md

REGRESS = pgxcrypto

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Add libraries that pgxcrypto_pwhash depends (or might depend) on into the
# shared library link.  (The order in which you list them here doesn't
# matter.)
SHLIB_LINK += $(LIBS) -lcrypt -lscrypt -lm -lcrypto -lz -largon2
ifeq ($(PORTNAME), win32)
SHLIB_LINK += $(filter -leay32, $(LIBS))
# those must be at the end
SHLIB_LINK += -lws2_32
endif
