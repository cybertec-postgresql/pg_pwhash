#include "pgxcrypto_scrypt.h"

#include "openssl/evp.h"
#include "openssl/kdf.h"

#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "utils/array.h"
#include "varatt.h"

#include "libscrypt.h"

PG_MODULE_MAGIC;

#define NUM_SCRYPT_OPTIONS 4
#define SCRYPT_WORK_FACTOR_N 16
#define SCRYPT_BLOCK_SIZE_r 8
#define SCRYPT_PARALLEL_FACTOR_p 1
#define SCRYPT_OUTPUT_VEC_LEN 64
#define SCRYPT_SALT_MAX_LEN 16l

static const char *SCRYPT_MAGIC_BYTE = "$7$";

enum scrypt_backend_types
{
  SCRYPT_BACKEND_LIBSCRYPT,
  SCRYPT_BACKEND_OPENSSL,
};

typedef enum scrypt_backend_types scrypt_backend_type_t;

struct pgxcrypto_option scrypt_options[] =
{
	{ "rounds", "ln", INT4OID,  {._int_value = SCRYPT_WORK_FACTOR_N } },
	{ "block_size", "r", INT4OID, {._int_value = SCRYPT_BLOCK_SIZE_r } },
	{ "parallelism", "p", INT4OID, {._int_value = SCRYPT_PARALLEL_FACTOR_p } },

	/*
	 * "backend" is not part of the scrypt specification but allows to identify
	 * if "openssl" or "libscrypt" implementation should be used
	 *
	 * Iff password hashes generated with this option name, be aware that
	 * they might be incompatible with other systems.
	 */
	{ "backend", "backend", INT4OID, { ._int_value = (int)SCRYPT_BACKEND_OPENSSL } }
};

/* Forwarded declarations */

static void
_scrypt_apply_options(Datum *options,
					  size_t numoptions,
					  int    *rounds,
					  int    *block_size,
					  int    *parallelism,
					  scrypt_backend_type_t *backend);
static char *
scrypt_libscrypt_internal(const char *pw,
						  const char *salt,
						  int rounds,
						  int block_size,
						  int parallelism);
static char *
scrypt_openssl_internal(const char *pw,
						const char *salt,
						int rounds,
						int block_size,
						int parallelism);

static void
simple_salt_parser_init(struct parse_salt_info *pinfo,
						struct pgxcrypto_option *options,
						size_t numoptions);

PG_FUNCTION_INFO_V1(pgxcrypto_scrypt);

/* ******************** Implementation starts here ******************** */

static void
simple_salt_parser_init(struct parse_salt_info *pinfo,
						struct pgxcrypto_option *options,
						size_t numoptions)
{
	pinfo->magic         = (char *)SCRYPT_MAGIC_BYTE;
	pinfo->magic_len     = 3;
	pinfo->algo_info_len = 0;
	pinfo->salt_len_min  = SCRYPT_SALT_MAX_LEN / 4;
	pinfo->salt          = NULL;
	pinfo->opt_str       = NULL;
	pinfo->num_sect      = 0;
	pinfo->opt_len       = 0;
	pinfo->options       = options;
	pinfo->num_parse_options = numoptions;
}

StringInfo
xgen_salt_scrypt(Datum *options, int numoptions)
{
	bool need_sep = false;
	int rounds;
	int block_size;
	int parallelism;
	scrypt_backend_type_t backend;
	StringInfo result;
	char salt_buf[SCRYPT_SALT_MAX_LEN + 1];
	char *salt_encoded;

	_scrypt_apply_options(options,
						  numoptions,
						  &rounds,
						  &block_size,
						  &parallelism,
						  &backend);

	/*
	 * Generate random bytes for the salt. Note that we just use up
	 * to SCRYPT_SALT_MAX_LEN bytes.
	 */
	result = makeStringInfo();
	memset(&salt_buf, '\0', SCRYPT_SALT_MAX_LEN + 1);

	if (!pg_strong_random(&salt_buf, SCRYPT_SALT_MAX_LEN))
	{
		elog(ERROR, "cannot generate random bytes for salt");
	}

	/* Convert bytes of the generated salt into base64 */
	salt_encoded = pgxcrypto_to_base64((const unsigned char*)salt_buf,
									   SCRYPT_SALT_MAX_LEN);

	/*
	 * Create the preamble and options
	 */
	appendStringInfoString(result, SCRYPT_MAGIC_BYTE);

	/* Generate the options part */
	if (rounds != SCRYPT_WORK_FACTOR_N)
	{
		appendStringInfo(result, "ln=%d", rounds);
		need_sep = true;
	}

	if (block_size != SCRYPT_BLOCK_SIZE_r)
	{
		if (need_sep)
			appendStringInfoCharMacro(result, ',');

		appendStringInfo(result, "r=%d", block_size);
		need_sep = true;
	}

	if (parallelism != SCRYPT_PARALLEL_FACTOR_p)
	{
		if (need_sep)
			appendStringInfoCharMacro(result, ',');

		appendStringInfo(result, "p=%d", parallelism);
	}

	/* Now append the generated salt string */
	appendStringInfoCharMacro(result, '$');
	appendStringInfoString(result, salt_encoded);

	/* ... and we're done */
	return result;
}

static void
_scrypt_apply_options(Datum *options,
					  size_t numoptions,
					  int    *rounds,
					  int    *block_size,
					  int    *parallelism,
					  scrypt_backend_type_t *backend)
{
	int i;

	/* Set defaults first */
	*rounds      = SCRYPT_WORK_FACTOR_N;
	*block_size  = SCRYPT_BLOCK_SIZE_r;
	*parallelism = SCRYPT_PARALLEL_FACTOR_p;
	*backend     = SCRYPT_BACKEND_LIBSCRYPT;

	for (i = 0; i < numoptions; i++)
	{
		char *str = TextDatumGetCString(options[i]);

		/* Lookup key/value separator */
		char *sep = strchr(str, '=');

		/* Found something? */
		if (sep)
		{
			*sep++ = '\0';
			struct pgxcrypto_option *opt = check_option(str,
														scrypt_options,
														NUM_SCRYPT_OPTIONS,
														true);

			if (opt != NULL)
			{
				if ((strncmp(opt->name, "rounds", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "ln", strlen(opt->alias))) == 0)
				{
					*rounds = pg_strtoint32(sep);
					continue;
				}

				if ((strncmp(opt->name, "block_size", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "r", strlen(opt->alias))) == 0)
				{
					*block_size = pg_strtoint32(sep);
					continue;
				}

				if ((strncmp(opt->name, "parallelism", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "p", strlen(opt->name))) == 0)
				{
					*parallelism = pg_strtoint32(sep);
					continue;
				}

				if ((strncmp(opt->name, "backend", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "backend", strlen(opt->alias)) == 0))
				{
					if (strncmp(sep, "openssl", strlen(sep)) == 0)
					{
						*backend = SCRYPT_BACKEND_OPENSSL;
					}
					else if (strncmp(sep, "libscrypt", strlen(sep)) == 0)
					{
						*backend = SCRYPT_BACKEND_LIBSCRYPT;
					}
					else
					{
						elog(ERROR,
							 "unknown value for option \"backend\": \"%s\"",
							 sep);
					}
				}
			}

		}
	}
}

static char *
scrypt_libscrypt_internal(const char *pw,
						  const char *salt,
						  int rounds,
						  int block_size,
						  int parallelism)
{
	char *output_encoded;

	char output[SCRYPT_OUTPUT_VEC_LEN];

	/* Init stuff */
	memset(output, '\0', SCRYPT_OUTPUT_VEC_LEN);

	if (libscrypt_scrypt((uint8_t *)pw, strlen(pw),
						 (uint8_t*)salt, strlen(salt), rounds,
						 block_size, parallelism,
						 (uint8_t *)&output, sizeof output) < 0)
	{
		elog(ERROR, "could not hash input");
	}

	/* Encode output */
	output_encoded = pgxcrypto_to_base64((unsigned char *)output, sizeof output);

	return output_encoded;
}

/*
 * pg_scrypt_libscrypt() generates a scrypt password hash based
 * on libscrypt.
 *
 * See https://github.com/technion/libscrypt/tree/master for more details.
 */
Datum
pgxcrypto_scrypt(PG_FUNCTION_ARGS)
{
	Datum *options = NULL;    /* ARRAY option elements */
	size_t noptions = 0;   /* number of options */
	text *password;
	text *salt;

	char *pw_buf;
	char *salt_buf;
	char *salt_decoded; /* decoded salt string */
	char salt_parsed[SCRYPT_SALT_MAX_LEN + 1];
	char *options_buf;
	char *digest;
	StringInfo resbuf; /* intermediate buffer to construct final password hash string */
	text      *result; /* hash string to return */

	int rounds;
	int block_size;
	int parallelism;
	scrypt_backend_type_t backend;

	struct parse_salt_info pinfo;

	password   = PG_GETARG_TEXT_PP(0);
	salt       = PG_GETARG_TEXT_PP(1);
	backend    = SCRYPT_BACKEND_LIBSCRYPT;
	memset(&salt_parsed, '\0', SCRYPT_SALT_MAX_LEN + 1);

	pw_buf = text_to_cstring(password);
	salt_buf = text_to_cstring(salt);

	simple_salt_parser_init(&pinfo, scrypt_options, NUM_SCRYPT_OPTIONS);
	simple_salt_parser(&pinfo, salt_buf);

	/* Extract options via parsed information */
	if (pinfo.opt_len > 0)
	{

		if (pinfo.opt_len < 0)
		{
			/* should not happen */
			elog(ERROR, "unexpected negative length of options string in salt");
		}

		options_buf = (char *) palloc(pinfo.opt_len + 1);
		memset(options_buf, '\0', pinfo.opt_len + 1);
		memcpy(options_buf, pinfo.opt_str, pinfo.opt_len);

		elog(DEBUG2, "extracted options from salt \"%s\"", options_buf);

		makeOptions(options_buf,
					pinfo.opt_len,
					&options,
					&noptions,
					NUM_SCRYPT_OPTIONS);
	}

	/* Extract the plain salt string from hashed input string */
	if (pinfo.salt_len > 0)
	{
		/* We ignore any bytes beyond SCRYPT_SALT_MAX_LEN */
		size_t len = Min(pinfo.salt_len, SCRYPT_SALT_MAX_LEN);
		memcpy(&salt_parsed, pinfo.salt, len);

		salt_decoded = (char *)pgxcrypto_from_base64(salt_parsed,
													 SCRYPT_SALT_MAX_LEN);
	}
	else
	{
		salt_decoded = "\0";
	}

	/* Sanity check, salt must not be null */
	if (salt_decoded == NULL)
	{
		elog(ERROR, "salt cannot be undefined");
	}

	/* Read and apply default and explicit option values */
	_scrypt_apply_options(options, noptions, &rounds, &block_size,
						  &parallelism, &backend);

	elog(DEBUG1, "scrypt opt: rounds=%d, block_size=%d, parallelism=%d",
		 rounds, block_size, parallelism);

	/*
	 * Calculate the digest, depending on the requested backend.
	 */
	if (backend == SCRYPT_BACKEND_LIBSCRYPT)
	{
		elog(DEBUG1, "using libscrypt backend");
		digest = scrypt_libscrypt_internal(pw_buf,
										   salt_decoded,
										   rounds,
										   block_size,
										   parallelism);
	}
	else {
		elog(DEBUG1, "using openssl backend");
		digest = scrypt_openssl_internal(pw_buf,
										 salt_decoded,
										 rounds,
										 block_size,
										 parallelism);
	}

	/*
	 * Build final hash string
	 */
	resbuf = makeStringInfo();

	/*
	 * An scrypt password hash string has the following format:
	 *
	 * $7$ln=<cost factor>,r=<block size>,p=<parallelism>$<max 16 bytes salt>$<password digest>
	 *
	 * NOTE:
	 *
	 * We support some additional optional parameters, but we don't output them
	 * for compatibility.
	 */
	appendStringInfo(resbuf, "%sln=%d,r=%d,p=%d$%s$%s",
					 SCRYPT_MAGIC_BYTE, rounds, block_size, parallelism,
					 salt_parsed, digest);

	/* Build the final text datum and we're done */
	result = (text *)palloc(resbuf->len + VARHDRSZ);
	SET_VARSIZE(result, resbuf->len + VARHDRSZ);
	memcpy(VARDATA(result), resbuf->data, resbuf->len);

	destroyStringInfo(resbuf);

	PG_RETURN_TEXT_P(result);
}

/*
 * pg_scrypt_openssl generates password based on OpenSSL's EVP_PKEY_SCRYPT KDF API.
 *
 * For details see
 *
 * https://docs.openssl.org/1.1.1/man7/scrypt/#copyright
 */
static char *
scrypt_openssl_internal(const char *pw,
						const char *salt,
						int rounds,
						int block_size,
						int parallelism)
{

	EVP_PKEY_CTX *ctx;
	size_t output_len;

	char output[SCRYPT_OUTPUT_VEC_LEN];
	char *output_b64;

	memset(output, '\0', SCRYPT_OUTPUT_VEC_LEN);
	output_len = sizeof output;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		elog(ERROR, "cannot initialize OpenSSL/scrypt KDF");
	}

	if (EVP_PKEY_CTX_set1_pbe_pass(ctx, pw, 8) <= 0)
	{
		elog(ERROR, "cannot call set1_pbe_pass()");
	}

	if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, (unsigned char *)salt, strlen(salt)) <= 0)
	{
		elog(ERROR, "cannot create salt");
	}

	if (EVP_PKEY_CTX_set_scrypt_N(ctx, rounds) <= 0)
	{
		elog(ERROR, "cannot set work factor N");
	}

	if (EVP_PKEY_CTX_set_scrypt_r(ctx, block_size) <= 0)
	{
		elog(ERROR, "cannot set block size r");
	}

	if (EVP_PKEY_CTX_set_scrypt_p(ctx, parallelism) <= 0)
	{
		elog(ERROR, "cannot set parallelization factor");
	}

	if (EVP_PKEY_derive(ctx, (unsigned char *)output, &output_len) <= 0)
	{
		elog(ERROR, "cannot derive test vector");
	}

	/*
	 * Encode digest
	 *
	 * XXX: Safe to cast length to int, since we can't exceed
	 *      SCRYPT_OUTPUT_VEC_LEN.
	 */
	output_b64 = pgxcrypto_to_base64((unsigned char *)output, (int)output_len);

	/* ..and we're done */
	return output_b64;

}
