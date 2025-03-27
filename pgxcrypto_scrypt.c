#include "pgxcrypto_scrypt.h"

#include <crypt.h>
#include "math.h"
#include "openssl/evp.h"
#include "openssl/kdf.h"

#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "utils/array.h"
#include "varatt.h"

#include "libscrypt.h"

PG_MODULE_MAGIC;

#define SCRYPT_WORK_FACTOR_N 16
#define SCRYPT_BLOCK_SIZE_r 8
#define SCRYPT_PARALLEL_FACTOR_p 1
#define SCRYPT_OUTPUT_VEC_LEN 32
#define SCRYPT_SALT_MAX_LEN 16l

/* Min value for rounds */
#define PGXCRYPTO_SCRYPT_MIN_ROUNDS 1

/*
 * Max value for rounds
 *
 * 32 is the max allowed value here defined by python's passlib, too.
 */
#define PGXCRYPTO_SCRYPT_MAX_ROUNDS 32

/* Min value for block size */
#define PGXCRYPTO_SCRYPT_MIN_BLOCK_SIZE 1

/*
 * Max value for block size
 *
 * XXX: This probably needs to be revisited some day, but i have no numbers what
 * a suitable max value would be atm.
 */
#define PGXCRYPTO_SCRYPT_MAX_BLOCK_SIZE 1024

/*
 * Min number of computing threads
 */
#define PGXCRYPTO_SCRYPT_MIN_PARALLELISM 1

/* Max number of computing threads */
#define PGXCRYPTO_SCRYPT_MAX_PARALLELISM 1024

enum scrypt_backend_types
{
  SCRYPT_BACKEND_LIBSCRYPT,
  SCRYPT_BACKEND_OPENSSL,
  SCRYPT_BACKEND_CRYPT
};

typedef enum scrypt_backend_types scrypt_backend_type_t;

#define NUM_SCRYPT_OPTIONS 4
static struct pgxcrypto_option scrypt_options[] =
{
	{ "rounds", "ln", INT4OID,  PGXCRYPTO_SCRYPT_MIN_ROUNDS,
	  PGXCRYPTO_SCRYPT_MAX_ROUNDS, {._int_value = SCRYPT_WORK_FACTOR_N } },
	{ "block_size", "r", INT4OID, PGXCRYPTO_SCRYPT_MIN_BLOCK_SIZE,
	  PGXCRYPTO_SCRYPT_MAX_BLOCK_SIZE, {._int_value = SCRYPT_BLOCK_SIZE_r } },
	{ "parallelism", "p", INT4OID, PGXCRYPTO_SCRYPT_MIN_PARALLELISM,
	  PGXCRYPTO_SCRYPT_MAX_PARALLELISM, {._int_value = SCRYPT_PARALLEL_FACTOR_p } },

	/*
	 * "backend" is not part of the scrypt specification but allows to identify
	 * if "openssl" or "libscrypt" implementation should be used
	 *
	 * Iff password hashes generated with this option name, be aware that
	 * they might be incompatible with other systems.
	 */
	{ "backend", "backend", INT4OID,
	  -1, -1, { ._int_value = (int)SCRYPT_BACKEND_OPENSSL } }
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
						const char *magic_string,
						size_t numoptions);

PG_FUNCTION_INFO_V1(pgxcrypto_scrypt);

/* ******************** Implementation starts here ******************** */

static void
simple_salt_parser_init(struct parse_salt_info *pinfo,
						struct pgxcrypto_option *options,
						const char *magic_string,
						size_t numoptions)
{
	Assert((pinfo != NULL) && (magic_string != NULL));

	pinfo->magic         = (char *)magic_string;
	pinfo->magic_len     = strlen(pinfo->magic);
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
xgen_salt_scrypt(Datum *options, int numoptions, const char *magic)
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
	appendStringInfoString(result, pgxcrypto_scrypt_magic_ident());

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
			struct pgxcrypto_option *opt;
			*sep++ = '\0';
			opt = check_option(str,
							   scrypt_options,
							   NUM_SCRYPT_OPTIONS,
							   true);

			if (opt != NULL)
			{
				if ((strncmp(opt->name, "rounds", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "ln", strlen(opt->alias))) == 0)
				{
					*rounds = pg_strtoint32(sep);

					/*
					 * Check min/max
					 */
					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *rounds,
										   opt->alias);

					continue;
				}

				if ((strncmp(opt->name, "block_size", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "r", strlen(opt->alias))) == 0)
				{
					*block_size = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *block_size,
										   opt->alias);

					continue;
				}

				if ((strncmp(opt->name, "parallelism", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "p", strlen(opt->name))) == 0)
				{
					*parallelism = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *parallelism,
										   opt->alias);
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
					else if (strncmp(sep, "crypt", strlen(sep)) == 0)
					{
						*backend = SCRYPT_BACKEND_CRYPT;
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
		else
		{
			/*
			 * Currently we always expect key=value notations in the options
			 * string, so throw an error at this point.
			 */
			ereport(ERROR,
					errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					errmsg("bogus option specified in salt"));
		}
	}
}

static char *
scrypt_crypt_internal(const char *pw,
					  const char *salt)
{

	return crypt(pw, salt);

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
						 (uint8_t*)salt, strlen(salt), pow(2, rounds),
						 block_size, parallelism,
						 (uint8_t *)&output, SCRYPT_OUTPUT_VEC_LEN) < 0)
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
	Datum *options          = NULL;    /* ARRAY option elements */
	size_t noptions         = 0;   /* number of options */
	int    salt_decoded_len = 0;
	text  *password;
	text  *salt;

	char *pw_buf;
	char *salt_buf;
	char *salt_decoded; /* decoded salt string */
	char *salt_parsed;
	//char salt_parsed[SCRYPT_SALT_MAX_LEN + 1];
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

	pw_buf = text_to_cstring(password);
	salt_buf = text_to_cstring(salt);

	simple_salt_parser_init(&pinfo,
							scrypt_options,
							pgxcrypto_scrypt_magic_ident(),
							NUM_SCRYPT_OPTIONS);
	simple_salt_parser(&pinfo, salt_buf);

	/* We require options and salt section at least for scrypt */
	if (pinfo.num_sect < 2){
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string does not have required settings or format"),
				errhint("The required format is \"$scrypt$ln=x,r=x,p=x$<salt>$\""));
	}

	/* Extract options via parsed information */
	if (pinfo.opt_len > 0)
	{

		if (pinfo.opt_len < 0)
		{
			/* should not happen */
			elog(ERROR, "unexpected negative length of options string in salt");
		}

		options_buf = (char *) palloc0(pinfo.opt_len + 1);
		memcpy(options_buf, pinfo.opt_str, pinfo.opt_len);

		elog(DEBUG2, "extracted options from salt \"%s\"", options_buf);

		makeOptions(options_buf,
					pinfo.opt_len,
					&options,
					&noptions,
					NUM_SCRYPT_OPTIONS);
	}

	/* Extract the plain salt string from hash input string */
	if (pinfo.salt_len > 0)
	{
		salt_parsed = (char *)palloc0(pinfo.salt_len + 1);
		memcpy(salt_parsed, pinfo.salt, pinfo.salt_len);

		elog(DEBUG2, "parsed salt: \"%s\"", salt_parsed);
		salt_decoded = (char *)pgxcrypto_from_base64(salt_parsed,
													 (int)(pinfo.salt_len),
													 &salt_decoded_len);
	}
	else
	{
		salt_decoded = "\0";
		salt_parsed  = "\0";
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
	switch(backend)
	{
		case SCRYPT_BACKEND_LIBSCRYPT:
		{
			elog(DEBUG1, "using libscrypt backend");
			digest = scrypt_libscrypt_internal(pw_buf,
											   salt_decoded,
											   rounds,
											   block_size,
											   parallelism);
			break;
		}
		case SCRYPT_BACKEND_OPENSSL:
		{
			elog(DEBUG1, "using openssl backend");
			digest = scrypt_openssl_internal(pw_buf,
											 salt_decoded,
											 rounds,
											 block_size,
											 parallelism);
			break;
		}
		case SCRYPT_BACKEND_CRYPT:
		{
			elog(DEBUG1, "using crypt backend");
			digest = scrypt_crypt_internal(pw_buf, salt_parsed);
			break;
		}
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
	appendStringInfo(resbuf,
					 "%sln=%d,r=%d,p=%d$%s$%s",
					 pgxcrypto_scrypt_magic_ident(),
					 rounds,
					 block_size,
					 parallelism,
					 pgxcrypto_to_base64((unsigned char *)salt_decoded,
										 (int)strlen(salt_decoded)), digest);

	/* Build the final text datum and we're done */
	result = (text *)palloc(resbuf->len + VARHDRSZ);
	SET_VARSIZE(result, resbuf->len + VARHDRSZ);
	memcpy(VARDATA(result), resbuf->data, resbuf->len);

	/* free our stuff */
	pfree(salt_parsed);
	pfree(salt_decoded);
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
	output_len = SCRYPT_OUTPUT_VEC_LEN;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		elog(ERROR, "cannot initialize OpenSSL/scrypt KDF");
	}

	if (EVP_PKEY_CTX_set1_pbe_pass(ctx, pw, strlen(pw)) <= 0)
	{
		elog(ERROR, "cannot call set1_pbe_pass()");
	}

	if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, (unsigned char *)salt, (int)strlen(salt)) <= 0)
	{
		elog(ERROR, "cannot create salt");
	}

	if (EVP_PKEY_CTX_set_scrypt_N(ctx, pow(2, rounds)) <= 0)
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
