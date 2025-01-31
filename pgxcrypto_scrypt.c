#include "pgxcrypto_scrypt.h"

#include "openssl/evp.h"
#include "openssl/kdf.h"

#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "varatt.h"

#include "libscrypt.h"

PG_MODULE_MAGIC;

struct pgxcrypto_option scrypt_options[] = {

		{ "rounds", INT4OID },
		{ "block_size", INT4OID },
		{ "parallelism", INT4OID }

};

text *
_scrypt_libscrypt_internal(const char *pw,
						   const char *salt,
						   int rounds,
						   int block_size,
						   int parallelism)
{

}

/*
 * pg_scrypt_libscrypt() generates a scrypt password hash based
 * on libscrypt.
 *
 * See https://github.com/technion/libscrypt/tree/master for more details.
 */
Datum
pg_scrypt_libscrypt(PG_FUNCTION_ARGS)
{
	text *password;
	text *salt;
	bytea *result;
	text *resb64;
	char *pw_buf;
	char *salt_buf;
	char output[SCRYPT_OUTPUT_VEC_LEN];

	memset(output, '\0', SCRYPT_OUTPUT_VEC_LEN);
	password = PG_GETARG_TEXT_PP(0);
	salt     = PG_GETARG_TEXT_PP(1);

	pw_buf = text_to_cstring(password);
	salt_buf = text_to_cstring(salt);

	if (libscrypt_scrypt((uint8_t *)pw_buf, strlen(pw_buf),
						 (uint8_t*)salt_buf, strlen(salt_buf), SCRYPT_WORK_FACTOR_N,
						 SCRYPT_BLOCK_SIZE_r, SCRYPT_PARALLEL_FACTOR_p,
						 (uint8_t *)&output, sizeof output) < 0)
	{
		elog(ERROR, "could not hash input");
	}

	/* Encode output */
	result = (bytea *) palloc(strlen(output) + VARHDRSZ);
	SET_VARSIZE(result, sizeof(output) + VARHDRSZ);
	memcpy(VARDATA(result), output, sizeof(output));

	resb64 = DatumGetTextP(DirectFunctionCall2(binary_encode,
											   PointerGetDatum(result),
											   PointerGetDatum(cstring_to_text("base64"))));

	PG_RETURN_TEXT_P(resb64);
}

/*
 * pg_scrypt_openssl generates password based on OpenSSL's EVP_PKEY_SCRYPT KDF API.
 *
 * For details see
 *
 * https://docs.openssl.org/1.1.1/man7/scrypt/#copyright
 */

Datum
pg_scrypt_openssl(PG_FUNCTION_ARGS)
{
	EVP_PKEY_CTX *ctx;
	text *password;
	text *salt;
	char *pw_buf;
	char *salt_buf;
	text *result;
	text *resb64;
	size_t output_len;

	char output[SCRYPT_OUTPUT_VEC_LEN];

	memset(output, '\0', SCRYPT_OUTPUT_VEC_LEN);
	output_len = sizeof output;
	password = PG_GETARG_TEXT_PP(0);
	salt     = PG_GETARG_TEXT_PP(1);

	pw_buf   = text_to_cstring(password);
	salt_buf = text_to_cstring(salt);

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		elog(ERROR, "cannot initialize OpenSSL/scrypt KDF");
	}

	if (EVP_PKEY_CTX_set1_pbe_pass(ctx, pw_buf, 8) <= 0)
	{
		elog(ERROR, "cannot call set1_pbe_pass()");
	}

	if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, (unsigned char *)salt_buf, strlen(salt_buf)) <= 0)
	{
		elog(ERROR, "cannot create salt");
	}

	if (EVP_PKEY_CTX_set_scrypt_N(ctx, SCRYPT_WORK_FACTOR_N) <= 0)
	{
		elog(ERROR, "cannot set work factor N");
	}

	if (EVP_PKEY_CTX_set_scrypt_r(ctx, SCRYPT_BLOCK_SIZE_r) <= 0)
	{
		elog(ERROR, "cannot set block size r");
	}

	if (EVP_PKEY_CTX_set_scrypt_p(ctx, SCRYPT_PARALLEL_FACTOR_p) <= 0)
	{
		elog(ERROR, "cannot set parallelization factor");
	}

	if (EVP_PKEY_derive(ctx, (unsigned char *)output, &output_len) <= 0)
	{
		elog(ERROR, "cannot derive test vector");
	}

	/*
	 * Built final bytea structure to return
	 */
	result = (bytea *) palloc(output_len + VARHDRSZ);
	SET_VARSIZE(result, output_len + VARHDRSZ);
	memcpy(VARDATA(result), output, output_len);

	memset(output, '\0', SCRYPT_OUTPUT_VEC_LEN);

	resb64 = DatumGetTextP(DirectFunctionCall2(binary_encode,
											   PointerGetDatum(result),
											   PointerGetDatum(cstring_to_text("base64"))));

	/* ..and we're done */
	PG_RETURN_TEXT_P(resb64);

}
