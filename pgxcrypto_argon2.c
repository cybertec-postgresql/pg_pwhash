//
// Created by bernd on 13.02.25.
//

#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "varatt.h"

#include "openssl/core_names.h"
#include "openssl/params.h"
#include "openssl/thread.h"
#include "openssl/kdf.h"

#include "argon2.h"

#include "pgxcrypto_poc.h"
#include "pgxcrypto_argon2.h"

/* Argon2 default option values */
#define ARGON2_SALT_MAX_LEN 64
#define ARGON2_THREADS 1     /* number of computing threads */
#define ARGON2_MEMORY_LANES 1  /* memory size / lanes, processed in parallel */

/*
 * Default number of iterations
 *
 * RFC 9106 says that this is the recommended setting for value t, see
 *
 * https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-algorithm
 *
 * section 7.4 (Recommendations) for details.
 *
 * The same applies to ARGON2_MEMORY_COST, which ideally is set to
 * (2^31) == 2GiB of memory. But since we might deal with memory constrained
 * systems we set it to much lower memory settings.
 */
#define ARGON2_ROUNDS 3
#define ARGON2_MEMORY_COST 4096 /* equals to 4MB of mem */

#define ARGON2_MAGIC_BYTE_ID "$argon2id$"
#define ARGON2_MAGIC_BYTE_D "$argon2d$"
#define ARGON2_MAGIC_BYTE_I "$argon2i$"

/*
 * The following are lower and upper limits allowed for settings for hash
 * computing. RFC 9106 allows far bigger values for some of these options. But
 * we put a far more strict boundary on some of them for practical reasons.
 *
 * See
 *
 * https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-algorithm
 *
 * for details again.
 */

/* Min threads allwoed for hashing */
#define PGXCRYPTO_ARGON2_MIN_THREADS 1

/* Max threads allowed for hashing */
#define PGXCRYPTO_ARGON2_MAX_THREADS 1024

/* Min number of lanes */
#define PGXCRYPTO_ARGON2_MIN_LANES PGXCRYPTO_ARGON2_MIN_THREADS

/* Max number of lanes */
#define PGXCRYPTO_ARGON2_MAX_LANES PGXCRYPTO_ARGON2_MAX_THREADS

/* Min number for memcost (memory size) */
#define PGXCRYPTO_ARGON2_MIN_MEMCOST 8

/*
 * Max number for memcost (memory size)
 *
 * We set this to match MaxAllocSize to match maximum request
 * for memory allocations allowed in the backend (as of writing this comment
 * around 1G).
 *
 * We can't rely on palloc() failing here, since allocations might be done
 * outside our control in the hashing libraries, so be sure we don't allow
 * arbitrary large values.
 */
#define PGXCRYPTO_ARGON2_MAX_MEMCOST 0x3fffffff

/* Min number of computation rounds */
#define PGXCRYPTO_ARGON2_MIN_ROUNDS 1

/* Max number of computation rounds */
#define PGXCRYPTO_ARGON2_MAX_ROUNDS INT_MAX

/* Min size of digest */
#define PGXCRYPTO_ARGON2_MIN_HASH_LEN 1

/*
 * Max size of digest
 *
 * Translates to
 */
#define PGXCRYPTO_ARGON2_MAX_HASH_LEN 0x00ffffff

/*
 * Default Argon2 version
 *
 * 0x13(19) is the default for OpenSSL and libargon2 backend
 *
 * Besides that, 0x10(16) might also be specified.
 */
#define ARGON2_DEFAULT_VERSION (unsigned int)0x13

/*
 * The output format for the Argon2 digest
 */
typedef enum
{
  ARGON2_OUTPUT_BASE64,
  ARGON2_OUTPUT_HEX
} argon2_output_format_t;

/*
 * Recommended tag length is 256 bits, see
 *
 * https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/#description
 */
#define ARGON2_HASH_LEN 32

static StringInfo
xgen_salt_argon_internal(Datum *options,
						 int numoptions);

PG_FUNCTION_INFO_V1(pgxcrypto_argon2);

/* Keep that in sync with below options array */
#define NUM_ARGON2_OPTIONS 7

static struct pgxcrypto_option argon2_options[] =
{
		{ "threads", "p", INT4OID, PGXCRYPTO_ARGON2_MIN_THREADS,
		  PGXCRYPTO_ARGON2_MAX_THREADS, { ._int_value = ARGON2_THREADS } },
		{ "lanes", "l", INT4OID, PGXCRYPTO_ARGON2_MIN_LANES,
		  PGXCRYPTO_ARGON2_MAX_LANES, { ._int_value = ARGON2_MEMORY_LANES } },
		{ "memcost", "m", INT4OID, PGXCRYPTO_ARGON2_MIN_MEMCOST,
		  PGXCRYPTO_ARGON2_MAX_MEMCOST, { ._int_value = ARGON2_MEMORY_COST } },
		{ "rounds", "t", INT4OID, PGXCRYPTO_ARGON2_MIN_ROUNDS,
		  PGXCRYPTO_ARGON2_MAX_ROUNDS, { ._int_value = ARGON2_ROUNDS } },
		{ "size", "size", INT4OID, PGXCRYPTO_ARGON2_MIN_HASH_LEN,
		  PGXCRYPTO_ARGON2_MAX_HASH_LEN, { ._int_value = ARGON2_HASH_LEN } },

		/* Specific parameters to pgxcrypto */
		{ "output_format", "output_format", -1, -1,
		  INT4OID, { ._int_value = ARGON2_OUTPUT_BASE64 } },
		/* Default backend should be kept in sync with the GUC pgxcrypto.argon2_backend */
		{ "backend", "backend", INT4OID, -1, -1,
		  { ._int_value = ARGON2_BACKEND_TYPE_OSSL } }
};

/* *********************** Forwarded declarations *********************** */

static
void simple_salt_parser_init(struct parse_salt_info *pinfo,
							 struct pgxcrypto_option *options,
							 size_t numoptions,
							 unsigned int argon2_version);

static
void _argon2_apply_options(Datum *options,
						   size_t numoptions,
						   int   *threads,
						   int   *lanes,
						   int   *memory_cost,
						   int   *rounds,
						   int   *size,
						   argon2_output_format_t  *output_format,
						   argon2_digest_backend_t *backend,
						   bool                    *explicit_backend_option);

/* *********************** Implementation *********************** */

static
void _argon2_apply_options(Datum *options,
						   size_t numoptions,
						   int   *threads,
						   int   *lanes,
						   int   *memory_cost,
						   int   *rounds,
						   int   *size,
						   argon2_output_format_t  *output_format,
						   argon2_digest_backend_t *backend,
						   bool                    *explicit_backend_option)
{
	int i;

	/* Set defaults first */
	*threads     = ARGON2_THREADS;
	*lanes       = ARGON2_MEMORY_LANES;
	*memory_cost = ARGON2_MEMORY_COST;
	*rounds      = ARGON2_ROUNDS;
	*size        = ARGON2_HASH_LEN;

	*output_format           = ARGON2_OUTPUT_BASE64;
	*backend                 = pgxcrypto_get_digest_backend();
	*explicit_backend_option = false;

	for (i = 0; i < numoptions; i++)
	{
		char *str = TextDatumGetCString(options[i]);

		/* Lookup value separator */
		char *sep = strchr(str, '=');

		if (sep)
		{
			struct pgxcrypto_option *opt;

			/* Make sure string is null terminated */
			*sep++ = '\0';
			opt = check_option(str,
							   argon2_options,
							   NUM_ARGON2_OPTIONS,
							   true);

			if (opt != NULL)
			{
				if ((strncmp(opt->name, "threads", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "p", strlen(opt->alias))) == 0)
				{
					*threads = pg_strtoint32(sep);

					/* Check allowed values for min/max */
					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *threads,
										   opt->alias);

					if (*lanes < *threads)
					{
						/*
						 * The number of lanes is currently smaller than the
						 * specified number of threads. Since argon2 requires this
						 * at least to be equal, we force lanes to be set to the same
						 * value than threads.
						 *
						 * Don't do this without giving the caller a warning that we do this,
						 * since the parameter lanes/l influences the final digest generation and
						 * produces different results depending on this.
						 */
						ereport(DEBUG1,
								errcode(ERRCODE_INVALID_PARAMETER_VALUE),
								errmsg("forcing parameter lanes/l equal to number of threads"),
								errhint("This means that the number of lanes(l=%d) must be equal or greater than threads(p=%d)",
										*lanes, *threads));
						*lanes = *threads;
					}

					continue;
				}

				if ((strncmp(opt->name, "lanes", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "l", strlen(opt->alias))) == 0)
				{
					*lanes = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *lanes,
										   opt->alias);

					/*
					 * We need to be careful when setting lanes explicitely,
					 * since there can't be lanes < threads.
					 */
					if (*lanes < *threads)
					{
						ereport(ERROR,
								errcode(ERRCODE_INVALID_PARAMETER_VALUE),
								errmsg("lanes must be equal or greater than threads, currently lanes(l=%d) < threads(p=%d)",
									   *lanes, *threads));
					}

					continue;
				}

				if ((strncmp(opt->name, "memcost", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "m", strlen(opt->alias)) == 0))
				{
					*memory_cost = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *memory_cost,
										   opt->alias);
					continue;
				}

				if ((strncmp(opt->name, "rounds", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "t", strlen(opt->alias)) == 0))
				{
					*rounds = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *rounds,
										   opt->alias);

					continue;
				}

				if ((strncmp(opt->name, "size", strlen(opt->name)) == 0)
					&& (strncmp(opt->alias, "size", strlen(opt->alias)) == 0))
				{
					*size = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min,
										   opt->max,
										   *size,
										   opt->alias);
					continue;
				}

				if (strncmp(opt->name, "output_format", strlen(opt->name)) == 0)
				{
					/* We support either "hex" or "base64" (the latter is the
					 * default */
					if (strncmp(sep, "base64", 6) == 0)
					{
						*output_format = ARGON2_OUTPUT_BASE64;
						continue;
					}
					if (strncmp(sep, "hex", 3) == 0)
					{
						*output_format = ARGON2_OUTPUT_HEX;
						continue;
					}

					/* Only reached in case of unknown output format */
					ereport(ERROR,
							errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							errmsg("invalid value for parameter \"output_format\": \"%s\"",
									sep));
				}

				if ((strncmp(opt->name, "backend", strlen(opt->alias)) == 0)
					|| (strncmp(opt->alias, "backend", strlen(opt->alias))) == 0)
				{
					/* Backend option was explicitely requested, make sure we remember */
					*explicit_backend_option = true;

					if (strncmp(sep, "openssl", 7) == 0)
					{
						*backend = ARGON2_BACKEND_TYPE_OSSL;
						continue;
					}

					if (strncmp(sep, "libargon2", 9) == 0)
					{
						*backend = ARGON2_BACKEND_TYPE_LIBARGON2;
						continue;
					}

					/* Only reached in case of unknown backend type */
					ereport(ERROR,
							errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							errmsg("unsupported backend type \"%s\"",
								   sep));
				}
			}

		}
	}
}

static
void simple_salt_parser_init(struct parse_salt_info *pinfo,
							 struct pgxcrypto_option *options,
							 size_t numoptions,
							 unsigned int argon2_version)
{
	pinfo->magic        = ARGON2_MAGIC_BYTE_ID;
	pinfo->magic_len    = strlen(pinfo->magic);

	/* Record optional version info for selected argon2 version */
	memset(pinfo->algo_info, '\0', PGXCRYPTO_ALGO_INFO_LEN + 1);
	pg_snprintf(pinfo->algo_info, PGXCRYPTO_ALGO_INFO_LEN, "v=%u$",
				argon2_version);
	pinfo->algo_info_len = strlen(pinfo->algo_info);

	pinfo->salt_len_min = ARGON2_SALT_MAX_LEN / 4;
	pinfo->salt         = NULL;
	pinfo->opt_str      = NULL;
	pinfo->num_sect     = 0;
	pinfo->opt_len      = 0;
	pinfo->options      = options;
	pinfo->num_parse_options = numoptions;
}

static StringInfo
xgen_salt_argon_internal(Datum *options,
						 int    numoptions)
{
	StringInfo result   = makeStringInfo();
	bool       need_sep = false;
	int threads;
	int lanes;
	int memcost;
	int rounds;
	int size;
	argon2_output_format_t  output_format;
	argon2_digest_backend_t backend;
	bool explicit_backend_option;

	_argon2_apply_options(options,
						  numoptions,
						  &threads,
						  &lanes,
						  &memcost,
						  &rounds,
						  &size,
						  &output_format,
						  &backend,
						  &explicit_backend_option);

	/*
	 * NOTE: The option string for argon2 has the following format:
	 *
	 * $m=<memcost>,t=<compute rounds>,p=<threads[,data=<data>]
	 *
	 * according to
	 *
	 * https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html
	 *
	 * We must compose the parameter string in the right order but still
	 * also support extensions with the lanes/l and size/size parameter.
	 * Note that the data=<data> parameter is also an extension to the format,
	 * but we don't implement that currently.
	 */

	if (lanes != ARGON2_MEMORY_LANES)
	{
		if (lanes != threads)
		{
			if (need_sep)
				appendStringInfoCharMacro(result, ',');

			appendStringInfo(result, "l=%d", lanes);
			need_sep = true;
		}

	}

	if (need_sep)
		appendStringInfoCharMacro(result, ',');
	appendStringInfo(result, "m=%d", memcost);
	need_sep = true;

	if (need_sep)
		appendStringInfoCharMacro(result, ',');
	appendStringInfo(result, "t=%d", rounds);
	need_sep = true;

	if (need_sep)
		appendStringInfoCharMacro(result, ',');
	appendStringInfo(result, "p=%d", threads);
	need_sep = true;

	if (size != ARGON2_HASH_LEN)
	{
		if (need_sep)
			appendStringInfoCharMacro(result, ',');

		appendStringInfo(result, "size=%d", size);
		need_sep = true;
	}

	if (explicit_backend_option)
	{
		char *backend_str = (backend == ARGON2_BACKEND_TYPE_OSSL ? "openssl" : "libargon2");

		if (need_sep)
			appendStringInfoCharMacro(result, ',');

		appendStringInfo(result, "backend=%s", backend_str);
		need_sep = true;
	}

	return result;
}

StringInfo xgen_salt_argon2(Datum *options, int numoptions, const char *magic)
{
	StringInfo result;
	StringInfo buf;

#define ARGON2_DEFAULT_SALT_LEN (ARGON2_SALT_MAX_LEN / 4)
	unsigned char  salt_buf[ ARGON2_DEFAULT_SALT_LEN + 1 ];
	char          *salt_encoded;

	/*
	 * Generate random bytes for the salt. We generate a random byte sequence
	 * of 16 bytes.
	 */
	result = makeStringInfo();
	memset(&salt_buf, '\0', ARGON2_DEFAULT_SALT_LEN + 1);

	if (!pg_strong_random(&salt_buf, ARGON2_DEFAULT_SALT_LEN))
	{
		elog(ERROR, "cannot generate random bytes for salt");
	}

	/* Convert binary string to base64 */
	salt_encoded = pgxcrypto_to_base64(salt_buf, ARGON2_DEFAULT_SALT_LEN);

	/*
	 * Prepare preamble. We don't apply the magic string blindly, check it
	 * before.
	 */
	if (magic == NULL)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("cannot generate a valid salt string with undefined magic string"));
	}

	if (strncmp(magic, ARGON2_MAGIC_BYTE_ID, strlen(ARGON2_MAGIC_BYTE_ID)) == 0)
	{
		appendStringInfoString(result, ARGON2_MAGIC_BYTE_ID);
	}
	else if (strncmp(magic, ARGON2_MAGIC_BYTE_D, strlen(ARGON2_MAGIC_BYTE_D)) == 0)
	{
		appendStringInfoString(result, ARGON2_MAGIC_BYTE_D);
	}
	else if (strncmp(magic, ARGON2_MAGIC_BYTE_I, strlen(ARGON2_MAGIC_BYTE_I)) == 0)
	{
		appendStringInfoString(result, ARGON2_MAGIC_BYTE_I);
	}
	else
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("unsupported magic string for argon2: \"%s\"",
					   magic));
	}

	/*
	 * We need the Argon2 version info. We generate always with the current
	 * version.
	 */
	appendStringInfo(result, "v=%u$", ARGON2_DEFAULT_VERSION);

	/*
	 * Create options string
	 */
	buf = xgen_salt_argon_internal(options,
								   numoptions);

	/* Append options string to the result */
	if (buf == NULL)
	{
		elog(ERROR, "could not generate options string for salt");
	}

	appendBinaryStringInfo(result, buf->data, buf->len);
	destroyStringInfo(buf);

	/*
	 * Not the generated salt string.
	 */
	appendStringInfoCharMacro(result, '$');
	appendStringInfoString(result, salt_encoded);

	/* and we're done */
	return result;
}

static
text *argon2_internal_libargon2(const char *magic,
								const char *pw,
								const char *salt,
								int threads,
								int lanes,
								int memcost,
								int rounds,
								int size,
								argon2_output_format_t format,
								unsigned int argon2_version)
{
	unsigned char *hash = palloc0(size);   /* result digest */
	argon2_context context;
	unsigned char *salt_decoded;
	int            salt_decoded_len;
	text *result;                 /* function result, text representation of digest */
	int rc;                       /* argon2 digest return code */

	/*
	 * Decode salt bytes from base64 first.
	 *
	 * XXX: It should be safe to cast the string length to int, since we
	 *      can't exceed ARGON2_SALT_MAX_LEN.
	 */
	salt_decoded = pgxcrypto_from_base64(salt,
										 (int)strlen(salt),
										 &salt_decoded_len);

	/*
	 * Taken from
	 * https://github.com/P-H-C/phc-winner-argon2
	 */
	context.out    = hash;  /* output array, at least HASHLEN in size */
	context.outlen = size; /* digest length */
	context.pwd    = (uint8_t *)pw; /* password array */
	context.pwdlen = strlen(pw); /* password length */
	context.salt   = salt_decoded;  /* salt array */
	context.saltlen = strlen((char *)salt_decoded); /* salt length */
	context.secret  = NULL;
	context.secretlen = 0;  /* optional secret data */
	context.ad        =	NULL;
	context.adlen     = 0; /* optional associated data */
	context.t_cost    =	rounds;
	context.m_cost    = memcost;
	context.lanes     = lanes;
	context.threads   = threads;
	context.version   = argon2_version; /* algorithm version */
	context.allocate_cbk = NULL;
	context.free_cbk     = NULL; /* custom memory allocation / deallocation functions */
	/* by default only internal memory is cleared (pwd is not wiped) */
	context.flags        = ARGON2_DEFAULT_FLAGS;

	/* Create argon2 hash context */
	if (strncmp(magic, "ARGON2ID", 8) == 0)
	{
		rc = argon2id_ctx(&context);
	}
	else if (strncmp(magic, "ARGON2I", 7) == 0)
	{
		rc = argon2i_ctx(&context);
	}
	else if (strncmp(magic, "ARGON2D", 7) == 0)
	{
		rc = argon2d_ctx(&context);
	}
	else
	{
		/* oops, shouldn't happen */
		elog(ERROR, "unexpected magic string \"%s\"", magic);
	}

	if (rc != ARGON2_OK)
	{
		elog(ERROR, "digest failed: %s", argon2_error_message(rc));
	}

	switch(format) {
		case ARGON2_OUTPUT_BASE64:
		{
			char  *resb64;
			size_t encoded_size;

			resb64 = pgxcrypto_to_base64(hash, size);
			encoded_size = strlen(resb64);

			result = (text *) palloc(encoded_size + VARHDRSZ);
			SET_VARSIZE(result, encoded_size + VARHDRSZ);
			memcpy(VARDATA(result), resb64, encoded_size);
			break;
		}
		case ARGON2_OUTPUT_HEX:
		{
			text *outputtohex;

			outputtohex = palloc(size + VARHDRSZ);
			SET_VARSIZE(outputtohex, size + VARHDRSZ);
			memcpy(VARDATA(outputtohex), hash, size);

			result = DatumGetTextP(DirectFunctionCall2(binary_encode,
													   PointerGetDatum(outputtohex),
													   PointerGetDatum(
															   cstring_to_text(
																	   "hex"))));
			break;
		}
	}

	return result;
}

/*
 * Hashes the password with the provided options via OpenSSL EVP_KDF_*
 * API.
 *
 * The caller is responsible to provide sane options.
 */
static
text *argon2_internal_ossl(const char *ossl_argon2_name,
						   const char *pw,
						   const char *salt,
						   int threads,
						   int lanes,
						   int memcost,
						   int rounds,
						   int size,
						   argon2_output_format_t format,
						   unsigned int argon2_version)
{
	EVP_KDF *ossl_kdf         = NULL;
	EVP_KDF_CTX *ossl_kdf_ctx = NULL;
	unsigned char *output;
	OSSL_PARAM parameters[8];
	OSSL_PARAM *ptr;

	text *result;
	unsigned char *salt_decoded;
	int            salt_decoded_len;

	/* Some initialization */
	output = palloc0(size + 1);

	/*
	 * Decode base64 salt string first.
	 *
	 * XXX: It should be safe to cast the salt length to int, since
	 *      we can't exceed ARGON2_SALT_MAX_LEN.
	 */
	salt_decoded = pgxcrypto_from_base64(salt, strlen(salt), &salt_decoded_len);

	/* The following code is taken from OpenSSL KDF documentation for
	 * ARGON2 and adjusted for our needs, see
	 *
	 * man 7 EVP_KDF-ARGON2
	 *
	 * for details.
	 */

	/* According to above manpage, this check is mandatory */
	if (OSSL_set_max_threads(NULL, threads) != 1)
	{
		elog(ERROR, "cannot set OpenSSL threads to %d", threads);
	}

	ptr = parameters;

	*ptr++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS,
										 (unsigned int *)&threads);
	*ptr++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,
										 (unsigned int *)&rounds);
	*ptr++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,
										 (unsigned int *)&lanes);
	*ptr++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST,
										 (unsigned int *)&memcost);
	*ptr++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_VERSION,
									   (unsigned int *)&argon2_version);
	*ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
											   (void *)salt_decoded,
											   strlen((char *)salt_decoded));
	*ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
											   (void *)pw,
											   strlen ((const char * )pw));
	*ptr++ = OSSL_PARAM_construct_end();

	if ((ossl_kdf = EVP_KDF_fetch(NULL, ossl_argon2_name, NULL)) == NULL)
	{
		goto err;
	}

	if ((ossl_kdf_ctx = EVP_KDF_CTX_new(ossl_kdf)) == NULL)
	{
		goto err;
	}

	if (EVP_KDF_derive(ossl_kdf_ctx, output, size, parameters) != 1)
	{
		goto err;
	}


	/* Seems everything went smooth, prepare the result */
	switch(format)
	{
		case ARGON2_OUTPUT_BASE64:
		{
			char  *resb64;
			size_t encoded_size;

			resb64 = pgxcrypto_to_base64(output, size);
			encoded_size = strlen(resb64);

			result = (text *) palloc(encoded_size + VARHDRSZ);
			SET_VARSIZE(result, encoded_size + VARHDRSZ);
			memcpy(VARDATA(result), resb64, encoded_size);
			break;
		}
		case ARGON2_OUTPUT_HEX:
		{
			text *outputtohex;

			outputtohex = palloc(size + VARHDRSZ);
			SET_VARSIZE(outputtohex, size + VARHDRSZ);
			memcpy(VARDATA(outputtohex), output, size);

			result = DatumGetTextP(DirectFunctionCall2(binary_encode,
													   PointerGetDatum(outputtohex),
													   PointerGetDatum(
															   cstring_to_text(
																	   "hex"))));
			break;
		}
	}

	return result;

err:
	EVP_KDF_free(ossl_kdf);
	EVP_KDF_CTX_free(ossl_kdf_ctx);
	OSSL_set_max_threads(NULL, 0);

	elog(ERROR, "creating argon2 password hash failed");
}

Datum
pgxcrypto_argon2(PG_FUNCTION_ARGS)
{
	Datum *options = NULL;
	size_t numoptions = 0;

	char *options_buf = NULL;
	char *ossl_argon2_name = "ARGON2ID";
	unsigned int argon2_version = ARGON2_DEFAULT_VERSION;

	struct parse_salt_info pinfo;

	char salt_buf[ARGON2_SALT_MAX_LEN + 1];

	StringInfo resbuf;
	text *result;
	text *hash;

	text *password;
	char *pw_cstr;
	text *salt;
	char *salt_cstr;

	/* Argon2 parameters for hash generation */
	int threads;
	int lanes;
	int memcost;
	int rounds;
	int size;
	argon2_output_format_t  output_format;
	argon2_digest_backend_t backend;
	bool                    explicit_backend_option;

	password = PG_GETARG_TEXT_PP(0);
	salt = PG_GETARG_TEXT_PP(1);

	memset(&salt_buf, '\0', ARGON2_SALT_MAX_LEN + 1);
	salt_cstr = text_to_cstring(salt);
	pw_cstr = text_to_cstring(password);

	/* Parse input salt string, prepare parser context. */
	simple_salt_parser_init(&pinfo, argon2_options, NUM_ARGON2_OPTIONS,
							ARGON2_DEFAULT_VERSION);

	/*
	 * Minimum length of salt is
 	 *
 	 * length(magic) + length(algo_info_len)
 	 *
 	 * Note that simple_salt_parser() below performs its own checks, too.
 	 */
	if (strlen(salt_cstr) < (pinfo.magic_len + pinfo.algo_info_len))
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string does not provide enough settings"));
	}

	/*
	 * We need the preamble of the salt to figure out the requested
	 * Argon2 algorithm to use.
	 */
	if (strncmp(salt_cstr, ARGON2_MAGIC_BYTE_ID, strlen(ARGON2_MAGIC_BYTE_ID)) == 0)
	{
		pinfo.magic = ARGON2_MAGIC_BYTE_ID;
		ossl_argon2_name = "ARGON2ID";
	}
	else if (strncmp(salt_cstr, ARGON2_MAGIC_BYTE_I, strlen(ARGON2_MAGIC_BYTE_I)) == 0)
	{
		pinfo.magic = ARGON2_MAGIC_BYTE_I;
		ossl_argon2_name = "ARGON2I";
	}
	else if (strncmp(salt_cstr, ARGON2_MAGIC_BYTE_D, strlen(ARGON2_MAGIC_BYTE_D)) == 0)
	{
		pinfo.magic = ARGON2_MAGIC_BYTE_D;
		ossl_argon2_name = "ARGON2D";
	}
	else
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("unsupported magic string in salt"));
	}

	/* Don't forget to adjust pinfo length of magic string */
	pinfo.magic_len = strlen(pinfo.magic);

	/* Parse the salt string with the now prepared parser context */
	simple_salt_parser(&pinfo, salt_cstr);

	/*
	 * Extract requested Argon2 version. If not found, silently assume
	 * current version.
	 *
	 * XXX: According to some sources, the version option is required since the
	 *      Argon2 v1.3 specification. It is tempting to assume that getting
	 *      a salt string without this might indicate to use some older specs,
	 *      but we ignore that fact and work with the current one implemented
	 *      here.
	 */
	if (strncmp((salt_cstr + pinfo.magic_len), "v=", 2) == 0)
	{
		/* extract the version number requested */
		char *v_ptr = salt_cstr + pinfo.magic_len;
		char *version_buf = (char *) palloc0(pinfo.algo_info_len + 1);
		char *sep;

		/* copy over the version string, but without the trailing $ . */
		memcpy(version_buf, v_ptr, pinfo.algo_info_len - 1);

		sep = strchr(version_buf, '=');

		if (sep)
		{
			*sep++ = '\0';
			argon2_version = (unsigned int)pg_strtoint32(sep);
		}

		/* Check version number, only 0x10 and 0x13 are currently supported */
		if ( (argon2_version != 0x10) && (argon2_version != 0x13) )
		{
			ereport(ERROR,
					errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					errmsg("unsupported argon2 version \"%u\"",
						   argon2_version),
					errhint("Supported versions are 16 and 19(default)"));
		}

		pfree(version_buf);
	}

	/* Handle options, if extracted by salt parser */
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

		/* Make an options array out of the string. */
		makeOptions(options_buf,
					pinfo.opt_len,
					&options,
					&numoptions,
					NUM_ARGON2_OPTIONS);

	}

	/* Extract plain salt string */
	if (pinfo.salt_len > 0)
	{
		/*
		 * Theoretically argon2 allows up to (2^32) - 1 bytes of salt length, but
		 * we limit this to a more practical limit.
		 */
		size_t len = Min(pinfo.salt_len, ARGON2_SALT_MAX_LEN);
		memcpy(salt_buf, pinfo.salt, len);

		elog(DEBUG2, "using salt \"%s\"", salt_buf);
	}
	else
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string cannot be empty"));
	}

	_argon2_apply_options(options, numoptions,
						  &threads, &lanes, &memcost, &rounds, &size,
						  &output_format, &backend, &explicit_backend_option);

	/* Calculate the password hash */
	elog(DEBUG2, "hashing password with Argon2 method \"%s\"",
		 ossl_argon2_name);

	switch(backend)
	{
		case ARGON2_BACKEND_TYPE_OSSL:
		{
			elog(DEBUG2, "using openssl backend for argon2 hashing");
			hash = argon2_internal_ossl(ossl_argon2_name,
										pw_cstr,
										salt_buf,
										threads,
										lanes,
										memcost,
										rounds,
										size,
										output_format,
										argon2_version);
			break;
		}
		case ARGON2_BACKEND_TYPE_LIBARGON2:
		{
			elog(DEBUG2, "using libargon2 backend for argon2 hashing");
			hash = argon2_internal_libargon2(ossl_argon2_name,
											 pw_cstr,
											 salt_buf,
											 threads,
											 lanes,
											 memcost,
											 rounds,
											 size,
											 output_format,
											 argon2_version);
			break;
		}
	}


	/*
	 * Construct the output string. We need to consider
	 * options and salt string
	 */
	resbuf = makeStringInfo();

	/*
	 * The salt string is mandatory, and we wouldn't ended up here if it
	 * wasn't present. But we need to check if we have to include the option
	 * string.
	 */
	if (pinfo.opt_len > 0)
	{
		appendStringInfo(resbuf, "%sv=%u$%s$%s$%s",
						 pinfo.magic,
						 argon2_version,
						 options_buf,
						 salt_buf,
						 text_to_cstring(hash));
	}
	else
	{
		appendStringInfo(resbuf, "%sv=%u$%s$%s",
						 pinfo.magic,
						 argon2_version,
						 salt_buf,
						 text_to_cstring(hash));
	}

	pfree(hash);
	result = (text *) palloc(resbuf->len + VARHDRSZ);
	SET_VARSIZE(result, resbuf->len + VARHDRSZ);
	memcpy(VARDATA(result), resbuf->data, resbuf->len);

	PG_RETURN_TEXT_P(result);
}

Datum
xcrypt_argon2(Datum password, Datum salt)
{
	return DirectFunctionCall2(pgxcrypto_argon2, password, salt);
}
