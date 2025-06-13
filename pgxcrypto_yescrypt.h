#ifndef PGXCRYPTO_POC_PGXCRYPT_YESCRYPT_H
#define PGXCRYPTO_POC_PGXCRYPT_YESCRYPT_H

#include "postgres.h"
#include "pgxcrypto_pwhash.h"

StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic);

Datum
xcrypt_yescrypt_crypt(Datum password, Datum salt);

#endif //PGXCRYPTO_POC_PGXCRYPT_YESCRYPT_H

