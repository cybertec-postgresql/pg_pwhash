/*
 * pg_bcrypt generates password based on OpenSSL's EVP_PKEY_SCRYPT KDF API.
 *
 * For details see
 *
 * https://docs.openssl.org/1.1.1/man7/scrypt/#copyright
 */

#include "postgres.h"
#include "fmgr.h"
#include "openssl/evp.h"
#include "openssl/kdf.h"
#include "utils/builtins.h"
#include "varatt.h"

PG_MODULE_MAGIC;

#define SCRYPT_BLOCK_SIZE_r 8
#define SCRYPT_PARALLEL_FACTOR_p 16
#define SCRYPT_WORK_FACTOR_N 16
#define SCRYPT_OUTPUT_VEC_LEN 32

PG_FUNCTION_INFO_V1(pg_scrypt);

static const char Base64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

static int
b64_encode(unsigned char const *src, size_t srclength, char *target, size_t targsize)
{
	size_t datalength = 0;
	unsigned char input[3];
	unsigned char output[4];
	unsigned int i;

	while (2 < srclength) {
		input[0] = *src++;
		input[1] = *src++;
		input[2] = *src++;
		srclength -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		target[datalength++] = Base64[output[2]];
		target[datalength++] = Base64[output[3]];
	}

	/* Now we worry about padding. */
	if (0 != srclength) {
		/* Get what's left. */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < srclength; i++)
			input[i] = *src++;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		if (srclength == 1)
			target[datalength++] = Pad64;
		else
			target[datalength++] = Base64[output[2]];
		target[datalength++] = Pad64;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0';	/* Returned value doesn't count \0. */
	return (int)(datalength);
}

Datum
pg_scrypt(PG_FUNCTION_ARGS)
{
	EVP_PKEY_CTX *ctx;
	text *password;
	char *pw_buf;
	char *salt;
	text *result;
	size_t output_len;

	char output_encoded[SCRYPT_OUTPUT_VEC_LEN];
	char output[SCRYPT_OUTPUT_VEC_LEN];

	output_len = sizeof output;
	password = PG_GETARG_TEXT_PP(0);
	memset(&output_encoded, '\0', SCRYPT_OUTPUT_VEC_LEN);

	pw_buf   = text_to_cstring(password);
	salt     = "NaCl";
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		elog(ERROR, "cannot initialize OpenSSL/scrypt KDF");
	}

	if (EVP_PKEY_CTX_set1_pbe_pass(ctx, pw_buf, 8) <= 0)
	{
		elog(ERROR, "cannot call set1_pbe_pass()");
	}

	if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, (unsigned char *)salt, 4) <= 0)
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
	 * Encode output
	 */
	b64_encode(output, output_len, output_encoded, output_len);

	/*
	 * Built final bytea structure to return
	 */
	result = (text *) palloc(output_len + VARHDRSZ);
	SET_VARSIZE(result, output_len + VARHDRSZ);
	memcpy(VARDATA(result), output_encoded, output_len);

	memset(output, '\0', SCRYPT_OUTPUT_VEC_LEN);

	/* ..and we're done */
	PG_RETURN_TEXT_P(result);

}
