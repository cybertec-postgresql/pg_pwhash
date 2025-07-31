#ifndef PWHASH_ARGON2_HXX
#define PWHASH_ARGON2_HXX

StringInfo xgen_salt_argon2(Datum *options, int numoptions, const char *magic);

Datum
xcrypt_argon2(Datum password, Datum salt);

#endif
