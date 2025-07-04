#include "pgxcrypto_scrypt.h"

#include <crypt.h>
#include <nodes/value.h>

#include "math.h"
#include "openssl/evp.h"
#include "openssl/kdf.h"

#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "varatt.h"

#include "libscrypt.h"

PG_MODULE_MAGIC;

#define SCRYPT_WORK_FACTOR_N 16
#define SCRYPT_BLOCK_SIZE_r 8
#define SCRYPT_PARALLEL_FACTOR_p 1
#define SCRYPT_OUTPUT_VEC_LEN 32
#define SCRYPT_SALT_MAX_LEN 16l

/**
 * Default magic string for scrypt.
 *
 * Note that crypt() wants to identify scrypt hashes via "$7$", whereas
 * the openssl and libscrypt backends want to have "$scrypt$".
 */
#define PGXCRYPTO_SCRYPT_MAGIC "$scrypt$"
#define PGXCRYPTO_SCRYPT_CRYPT_MAGIC "$7$"

/*
 * A crypt() compatible salt string must be in the format
 * $7$[./A-Za-z0-9]{11,97}$[./A-Za-z0-9]{43}
 *
 * (see man 5 crypt for details)
 *
 * Thus we request at lest 14 bytes of length.
 */
#define PGXCRYPTO_SCRYPT_CRYPT_MIN_SALT_LEN 14

/* Min value for rounds */
#define PGXCRYPTO_SCRYPT_MIN_ROUNDS 1

/*
 * Max value for rounds
 *
 * NOTE:
 *
 * 32 is the max allowed value here defined by python's passlib, but it seems we cannot do more
 * than currently 20 when using OpenSSL. libscrypt allows more, so be en par with python.
 */
#define PGXCRYPTO_SCRYPT_MAX_ROUNDS 32

/* Min value for block size */
#define PGXCRYPTO_SCRYPT_MIN_BLOCK_SIZE 1

/*
 * Minimum rounds for crypt()
 */
#define PGXCRYPTO_SCRYPT_CRYPT_MIN_ROUNDS 6

/*
 * Maximum rounds for crypt()
 */
#define PGXCRYPTO_SCRYPT_CRYPT_MAX_ROUNDS 11

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
  SCRYPT_BACKEND_OPENSSL
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

#define NUM_SCRYPT_CRYPT_OPTIONS 1
static struct pgxcrypto_option scrypt_crypt_options[] =
{
	{
		"rounds", "rounds", INT4OID, PGXCRYPTO_SCRYPT_CRYPT_MIN_ROUNDS,
		PGXCRYPTO_SCRYPT_CRYPT_MAX_ROUNDS, { ._int_value =  PGXCRYPTO_SCRYPT_MIN_ROUNDS }
	}
};

/* Forwarded declarations */
PG_FUNCTION_INFO_V1(pgxcrypto_scrypt);
PG_FUNCTION_INFO_V1(pgxcrypto_scrypt_crypt);

static void
_scrypt_apply_options(Datum *options,
					  size_t numoptions,
					  int    *rounds,
					  int    *block_size,
					  int    *parallelism,
					  scrypt_backend_type_t *backend);

static void
_scrypt_apply_crypt_options(Datum *options,
							int num_options,
							int *rounds);

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

/* ******************** Implementation starts here ******************** */

/**
 * Calculates the working factor scrypt used for openssl/libscrypt backend. Result
 * is 2^exp. If exp is larger than PGXCRYPTO_SCRYPT_MAX_ROUNDS, exp will be truncated to the
 * maximum allowed value.
 *
 * @param exp The cost exponent
 * @return working factor N for scrypt
 */
static int calc_working_factor(int exp)
{
	int exp_max = Min(exp, PGXCRYPTO_SCRYPT_MAX_ROUNDS);
	int result  = 1;
	int i;

	for (i = 0; i < exp_max; i++) {
		result *= 2;
	}

	return result;
}

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
	pinfo->salt_len      = 0;
	pinfo->opt_str       = NULL;
	pinfo->num_sect      = 0;
	pinfo->opt_len       = 0;
	pinfo->options       = options;
	pinfo->num_parse_options = numoptions;
}

/**
 * Returns an valid StringInfo string buffer with a fully
 * initialized salt string with the following format:
 *
 * @param rounds Compute factor
 * @param block_size Block size for hashing
 * @param parallelism Number of threads to use
 * @param salt The generated salt (base64 encoded)
 * @param backend The used backend for hashing
 * @param include_backend_option Final salt string should include backend option
 * @return A fully initialized StringInfo pointer
 */
static StringInfo xgen_gen_salt_string(int rounds,
									   int block_size,
									   int parallelism,
									   const char *salt,
									   scrypt_backend_type_t backend,
									   bool include_backend_option)
{
	char *magic_string = PGXCRYPTO_SCRYPT_MAGIC;
	StringInfo result;

	result = makeStringInfo();

	/*
	 * Create the preamble and options
	 */
	appendStringInfoString(result, magic_string);

	switch(backend)
	{
		case SCRYPT_BACKEND_LIBSCRYPT:
			/* fall through */
		case SCRYPT_BACKEND_OPENSSL: {
			if (include_backend_option)
			{
				appendStringInfo(result,
								 "ln=%d,r=%d,p=%d,backend=%s$%s$",
								 rounds,
								 block_size,
								 parallelism,
								 ((backend == SCRYPT_BACKEND_LIBSCRYPT) ? "libscrypt" : "openssl"),
								 salt);
			}
			else
			{
				appendStringInfo(result,
								 "ln=%d,r=%d,p=%d$%s$",
								 rounds,
								 block_size,
								 parallelism,
								 salt);
			}
			break;
		}

	}

	return result;
}

/**
 * Wrapper function for libc's crypt_gensalt()
 *
 * @param rounds Processing cost for salt
 * @return A fully initialized StringInfo buffer
 */
StringInfo
xgen_crypt_gensalt_scrypt(Datum *options, int num_options, const char *magic_string)
{
#ifndef _PGXCRYPTO_CRYPT_SCRYPT_SUPPORT
	ereport(ERROR,
			errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			errmsg("this platform does not provide crypt support for scrypt"));
#else
	StringInfo result;
	char      *salt_buf;
	int        rounds;

	/* Force crypt() compatible magic string */
	if (magic_string == NULL || strncmp(magic_string, "$7$", 3) != 0)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("invalid magic string"));
	}

	_scrypt_apply_crypt_options(options, num_options, &rounds);

	result = makeStringInfo();
	salt_buf = crypt_gensalt("$7$", rounds, NULL, 0);

	if ( errno == EINVAL || errno == ENOMEM )
	{
		char *err_string = strerror(errno);

		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not create salt"),
				errdetail("Internal error: %s", err_string));
	}

	if (salt_buf == NULL)
	{
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not create salt"));
	}

	appendStringInfoString(result, salt_buf);
	return result;
#endif
}

StringInfo
xgen_salt_scrypt(Datum *options, int numoptions, const char *magic)
{
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
	memset(&salt_buf, '\0', SCRYPT_SALT_MAX_LEN + 1);

	if (!pg_strong_random(&salt_buf, SCRYPT_SALT_MAX_LEN))
	{
		elog(ERROR, "cannot generate random bytes for salt");
	}

	/* Convert bytes of the generated salt into base64 */
	salt_encoded = pgxcrypto_to_base64((const unsigned char*)salt_buf,
									   SCRYPT_SALT_MAX_LEN);

	result = xgen_gen_salt_string(rounds,
								  block_size,
								  parallelism,
								  salt_encoded,
								  backend,
								  true);

	/* ... and we're done */
	return result;
}

static void
_scrypt_apply_crypt_options(Datum *options,
							int num_options,
							int *rounds)
{
	int i;
	*rounds = PGXCRYPTO_SCRYPT_CRYPT_MIN_ROUNDS;

	for (i = 0; i < num_options; i++)
	{
		char *str = TextDatumGetCString(options[i]);

		/* Lookup key/value separator */
		char *sep = strchr(str, '=');

		if (sep) {
			struct pgxcrypto_option *opt;
			*sep++ = '\0';
			opt = check_option(str,
							   scrypt_crypt_options,
							   NUM_SCRYPT_CRYPT_OPTIONS,
							   true);

			if (opt != NULL)
			{
				if (strncmp(opt->name, "rounds", strlen(opt->name)) == 0)
				{
					*rounds = pg_strtoint32(sep);

					pgxcrypto_check_minmax(PGXCRYPTO_SCRYPT_CRYPT_MIN_ROUNDS,
										   PGXCRYPTO_SCRYPT_CRYPT_MAX_ROUNDS,
										   *rounds,
										   "rounds");
				}
			}
		}
	}
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
scrypt_libscrypt_internal(const char *pw,
						  const char *salt,
						  int rounds,
						  int block_size,
						  int parallelism)
{
	char output[SCRYPT_OUTPUT_VEC_LEN] = {0};
	char *output_encoded;

	if (libscrypt_scrypt((uint8_t *)pw, strlen(pw),
	                     (uint8_t*)salt, strlen(salt), calc_working_factor(rounds),
	                     block_size, parallelism,
	                     (uint8_t *)&output, SCRYPT_OUTPUT_VEC_LEN) < 0)
	{
		elog(ERROR, "could not hash input");
	}

	/* Encode output */
	output_encoded = pgxcrypto_to_base64((unsigned char *)output, sizeof output);

	return output_encoded;
}

Datum
pgxcrypto_scrypt_crypt(PG_FUNCTION_ARGS)
{
#ifndef _PGXCRYPTO_CRYPT_SCRYPT_SUPPORT
	ereport(ERROR,
			errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			errmsg("this platform does not provide crypt support for scrypt"));
#else
	text *password;
	text *settings;
	text *result;
	char *hash;
	char *pw_cstr;
	char *settings_cstr;

	password = PG_GETARG_TEXT_P(0);
	settings = PG_GETARG_TEXT_P(1);

	pw_cstr = text_to_cstring(password);
	settings_cstr = text_to_cstring(settings);

	if (strlen(settings_cstr) < PGXCRYPTO_SCRYPT_CRYPT_MIN_SALT_LEN)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string must be at least %d bytes",
						PGXCRYPTO_SCRYPT_CRYPT_MIN_SALT_LEN));
	}

	/* Force crypt() compatible magic string */
	if (strncmp(settings_cstr, "$7$", 3) != 0)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("invalid magic string for crypt()"));
	}

	hash = crypt(pw_cstr, settings_cstr);

	if ( errno == EINVAL )
	{
		char *errm = strerror(errno);
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("error creating password hash with crypt()"),
				errdetail("Internal error using crypt(): %s", errm));
	}

	if (hash == NULL)
	{
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not create password hash via crypt()"));
	}

	/*
	 * According to crypt(3) documentation, implementations of crypt() might return an
	 * invalid hash starting with '*'. So check for this, too.
	 */
	if (hash[0] == '*')
	{
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("error creating password hash with crypt()"));
	}

	/* Everything seems ok, prepare result Datum */
	result = (text *)palloc(VARHDRSZ + strlen(hash));
	SET_VARSIZE(result, VARHDRSZ + strlen(hash));
	memcpy(VARDATA(result), hash, strlen(hash));

	PG_RETURN_TEXT_P(result);
#endif
}

/**
 * pg_scrypt_libscrypt() generates a scrypt password hash based
 * on libscrypt of openssl.
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
	char *digest = NULL;
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
							PGXCRYPTO_SCRYPT_MAGIC,
							NUM_SCRYPT_OPTIONS);

	simple_salt_parser(&pinfo, salt_buf);

	/* We require options and salt section at least for scrypt */
	if (pinfo.salt_len <= 0) {
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string does not have required settings or format"));
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
	salt_parsed = (char *)palloc0(pinfo.salt_len + 1);
	memcpy(salt_parsed, pinfo.salt, pinfo.salt_len);

	elog(DEBUG2, "parsed salt: \"%s\"", salt_parsed);
	salt_decoded = (char *)pgxcrypto_from_base64(salt_parsed,
												 (int)(pinfo.salt_len),
												 &salt_decoded_len);

	/* Sanity check, salt must not be null. Should not happen ... */
	if (salt_decoded == NULL)
	{
		elog(ERROR, "salt cannot be undefined");
	}

	/* Read and apply default and explicit option values */
	_scrypt_apply_options(options, noptions, &rounds, &block_size,
						  &parallelism, &backend);

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
	}

	if (unlikely(digest == NULL))
	{
		elog(ERROR, "unrecognized backend type");
	}

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
	resbuf = xgen_gen_salt_string(rounds,
								  block_size,
								  parallelism,
								  salt_parsed,
								  backend,
								  false);

	/* Don't forget to adjust the digest */
	appendStringInfoString(resbuf, digest);

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

	if (EVP_PKEY_CTX_set1_pbe_pass(ctx, pw, (int)strlen(pw)) <= 0)
	{
		elog(ERROR, "cannot call set1_pbe_pass()");
	}

	if (EVP_PKEY_CTX_set1_scrypt_salt(ctx, (unsigned char *)salt, (int)strlen(salt)) <= 0)
	{
		elog(ERROR, "cannot create salt");
	}

	if (EVP_PKEY_CTX_set_scrypt_N(ctx, calc_working_factor(rounds)) <= 0)
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

Datum
xcrypt_scrypt(Datum password, Datum salt)
{
	return DirectFunctionCall2(pgxcrypto_scrypt, password, salt);
}

Datum
xcrypt_scrypt_crypt(Datum password, Datum salt)
{
	return DirectFunctionCall2(pgxcrypto_scrypt_crypt, password, salt);
}
