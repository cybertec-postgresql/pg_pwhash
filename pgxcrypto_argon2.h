//
// Created by bernd on 13.02.25.
//

#ifndef PGXCRYPTO_POC_PGXCRYPTO_ARGON2_HXX
#define PGXCRYPTO_POC_PGXCRYPTO_ARGON2_HXX

StringInfo xgen_salt_argon2(Datum *options, int numoptions, const char *magic);

Datum
xcrypt_argon2(Datum password, Datum salt);

#endif //PGXCRYPTO_POC_PGXCRYPTO_ARGON2_HXX
