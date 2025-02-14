PG_CONFIG ?= pg_config
MODULE_big = pgxcrypto_poc
OBJS = pgxcrypto_yescrypt.o pgxcrypt_argon2.o pgxcrypto_scrypt.o pgxcrypto_poc.o $(WIN32RES)
PGFILEDESC = "pgxcrypto_poc - A POC implementation based on OpenSSL for sha{256|521}crypt"

EXTENSION = pgxcrypto_poc
DATA = pgxcrypto_poc--1.0.sql
DOCS = pxcrypto_poc.md

REGRESS = pgxcrypto_poc

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Add libraries that pgcrypto depends (or might depend) on into the
# shared library link.  (The order in which you list them here doesn't
# matter.)
SHLIB_LINK += $(filter -lcrypto -lz, $(LIBS))
ifeq ($(PORTNAME), win32)
SHLIB_LINK += $(filter -leay32, $(LIBS))
# those must be at the end
SHLIB_LINK += -lws2_32
endif
