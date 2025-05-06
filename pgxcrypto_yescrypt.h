#ifndef PGXCRYPTO_POC_PGXCRYPT_YESCRYPT_H
#define PGXCRYPTO_POC_PGXCRYPT_YESCRYPT_H

#include "postgres.h"
#include "pgxcrypto_poc.h"

StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic);

#endif //PGXCRYPTO_POC_PGXCRYPT_YESCRYPT_H

