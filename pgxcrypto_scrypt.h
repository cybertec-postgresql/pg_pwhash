#ifndef PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H
#define PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H

#include "postgres.h"
#include "fmgr.h"

#include "pgxcrypto_poc.h"

StringInfo
xgen_salt_scrypt(Datum *generator_options, int numoptions, const char *magic);
StringInfo
xgen_crypt_gensalt_scrypt(Datum *options, int num_options, const char *magic_string);

Datum
xcrypt_scrypt(Datum password, Datum salt);

Datum
xcrypt_scrypt_crypt(Datum password, Datum salt);

#endif
