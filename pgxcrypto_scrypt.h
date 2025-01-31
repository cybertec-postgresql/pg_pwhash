#ifndef PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H
#define PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H

#include "postgres.h"
#include "fmgr.h"

#include "pgxcrypto_poc.h"

#define SCRYPT_BLOCK_SIZE_r 8
#define SCRYPT_PARALLEL_FACTOR_p 1
#define SCRYPT_WORK_FACTOR_N 16
#define SCRYPT_OUTPUT_VEC_LEN 64

PG_FUNCTION_INFO_V1(pg_scrypt_openssl);
PG_FUNCTION_INFO_V1(pg_scrypt_libscrypt);

#endif //PGXCRYPTO_POC_PGXCRYPTO_SCRYPT_H
