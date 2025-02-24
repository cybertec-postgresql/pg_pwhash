#ifndef PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H
#define PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H

#include "postgres.h"
#include "fmgr.h"

#include "pgxcrypto_poc.h"

StringInfo
xgen_salt_scrypt(Datum *generator_options, int numoptions);

#endif
