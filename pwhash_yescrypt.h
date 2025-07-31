#ifndef PWHASH_YESCRYPT_H
#define PWHASH_YESCRYPT_H

#include "postgres.h"
#include "pg_pwhash.h"

StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic);

Datum
xcrypt_yescrypt_crypt(Datum password, Datum salt);

#endif
