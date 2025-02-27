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

#include "pgxcrypto_poc.h"
#include "pgxcrypto_argon2.h"

/* Argon2 default option values */
#define ARGON2_SALT_MAX_LEN 64
#define ARGON2_THREADS 1     /* number of computing threads */
#define ARGON2_MEMORY_LANES 2    /* memory size / lanes, processed in parallel */

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
 * systems we set it to the 2nd recommended setting which much lower memory
 * requirement.
 */
#define ARGON2_ROUNDS 3
#define ARGON2_MEMORY_COST 65536 /* equals to 64Mb of mem */

#define ARGON2_MAGIC_BYTE_ID "$argon2id$"
#define ARGON2_MAGIC_BYTE_D "$argon2d"

/*
 * The output format for the Argon2 digest
 */
typedef enum
{
  ARGON2_OUTPUT_BASE64,
  ARGON2_OUTPUT_HEX
} argon2_output_format_t;

/*
 * Backend type to use for Argon2, currently
 *
 * - OpenSSL
 * - libargon2
 *
 * are supported
 */
typedef enum {
  ARGON2_BACKEND_TYPE_OSSL,
  ARGON2_BACKEND_TYPE_LIBARGON2,
} argon2_digest_backend_t;

/*
 * Recommended tag length is 256 bits, see
 *
 * https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/#description
 *
 * But we're using 128 bit for now to keep the resulting hash default length
 * more compact.
 */
#define ARGON2_HASH_LEN 16

static StringInfo
xgen_salt_argon_internal(char *algorithm,
						 Datum *options,
						 int numoptions);

PG_FUNCTION_INFO_V1(pgxcrypto_argon2);

/* Base64 lookup table */
static unsigned char _crypt_itoa64[64 + 1] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Keep that in sync with below options array */
#define NUM_ARGON2_OPTIONS 7

struct pgxcrypto_option argon2_options[] =
{
		{ "threads", "p", INT4OID, { ._int_value = ARGON2_THREADS } },
		{ "lanes", "l", INT4OID, { ._int_value = ARGON2_MEMORY_LANES } },
		{ "memcost", "m", INT4OID, { ._int_value = ARGON2_MEMORY_COST } },
		{ "rounds", "t", INT4OID, { ._int_value = ARGON2_ROUNDS } },
		{ "size", "size", INT4OID, { ._int_value = ARGON2_HASH_LEN } },

		/* Specific parameters to pgxcrypto */
		{ "output_format", "output_format", INT4OID, { ._int_value = ARGON2_OUTPUT_BASE64 } },
		{ "backend", "backend", INT4OID, { ._int_value = ARGON2_BACKEND_TYPE_OSSL } }
};

/* *********************** Forwarded declarations *********************** */

static
void simple_salt_parser_init(struct parse_salt_info *pinfo,
							 struct pgxcrypto_option *options,
							 size_t numoptions);

static
void _argon2_apply_options(Datum *options,
						   size_t numoptions,
						   int   *threads,
						   int   *lanes,
						   int   *memory_cost,
						   int   *rounds,
						   int   *size,
						   argon2_output_format_t *output_format,
						   argon2_digest_backend_t *backend);

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
						   argon2_digest_backend_t *backend)
{
	int i;

	/* Set defaults first */
	*threads     = ARGON2_THREADS;
	*lanes       = ARGON2_MEMORY_LANES;
	*memory_cost = ARGON2_MEMORY_COST;
	*rounds      = ARGON2_ROUNDS;
	*size        = ARGON2_HASH_LEN;

	*output_format = ARGON2_OUTPUT_BASE64;
	*backend       = ARGON2_BACKEND_TYPE_OSSL;

	for (i = 0; i < numoptions; i++)
	{
		char *str = TextDatumGetCString(options[i]);

		/* Lookup value separator */
		char *sep = strchr(str, '=');

		if (sep)
		{
			/* Make sure string is null terminated */
			*sep++ = '\0';
			struct pgxcrypto_option *opt = check_option(str,
					argon2_options,
					NUM_ARGON2_OPTIONS,
					true);

			if (opt != NULL)
			{
				if ((strncmp(opt->name, "threads", strlen(opt->name)) == 0)
					|| (strncmp(opt->alias, "p", strlen(opt->alias))) == 0)
				{
					*threads = pg_strtoint32(sep);
					continue;
				}

				if ((strncmp(opt->name, "lanes", strlen(opt->name)) == 0)
					|| (strncmp(opt->alias, "l", strlen(opt->name))) == 0)
				{
					*lanes = pg_strtoint32(sep);
					continue;
				}

				if (strncmp(opt->name, "memcost", strlen(opt->name)) == 0)
				{
					*memory_cost = pg_strtoint32(sep);
					continue;
				}

				if (strncmp(opt->name, "rounds", strlen(opt->name)) == 0)
				{
					*rounds = pg_strtoint32(sep);
					continue;
				}

				if (strncmp(opt->name, "size", strlen(opt->name)) == 0)
				{
					*size = pg_strtoint32(sep);
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
					else if (strncmp(sep, "hex", 3) == 0)
					{
						*output_format = ARGON2_OUTPUT_HEX;
						continue;
					}
					else
					{
						ereport(ERROR,
								errcode(ERRCODE_INVALID_PARAMETER_VALUE),
								errmsg("invalid value for parameter \"output_format\": \"%s\"",
									   sep));
					}
				}

				if ((strncmp(opt->name, "backend", strlen(opt->alias)) == 0)
					|| (strncmp(opt->alias, "backend", strlen(opt->alias))) == 0)
				{
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
				}
			}

		}
	}
}

static
void simple_salt_parser_init(struct parse_salt_info *pinfo,
							 struct pgxcrypto_option *options,
							 size_t numoptions)
{
	pinfo->magic        = (char *)ARGON2_MAGIC_BYTE_ID;
	pinfo->magic_len    = strlen(pinfo->magic);
	pinfo->salt_len_min = ARGON2_SALT_MAX_LEN / 4;
	pinfo->salt         = NULL;
	pinfo->opt_str      = NULL;
	pinfo->num_sect     = 0;
	pinfo->opt_len      = 0;
	pinfo->options      = options;
	pinfo->num_parse_options = numoptions;
}

static StringInfo
xgen_salt_argon_internal(char  *algorithm,
						 Datum *options,
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

	_argon2_apply_options(options,
						  numoptions,
						  &threads,
						  &lanes,
						  &memcost,
						  &rounds,
						  &size,
						  &output_format,
						  &backend);

	/*
	 * NOTE: The option string for argon2 has the following format:
	 *
	 * $m=<memcost>,t=<compute rounds>,p=<threads[,data=<data>
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
		if (need_sep)
			appendStringInfoCharMacro(result, ',');

		appendStringInfo(result, "l=%d", lanes);
		need_sep = true;
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

	return result;
}

StringInfo xgen_salt_argon2id(Datum *options, int numoptions)
{
	StringInfo result;
	StringInfo buf;
	int i;

#define ARGON2_DEFAULT_SALT_LEN (ARGON2_SALT_MAX_LEN / 4)
	char      salt_buf[ ARGON2_DEFAULT_SALT_LEN + 1 ];
	char     *s_ptr;

	/*
	 * Generate random bytes for the salt. We generate a random byte sequence
	 * of 16 bytes.
	 */
	result = makeStringInfo();
	memset(&salt_buf, '\0', ARGON2_DEFAULT_SALT_LEN + 1);

	if (!pg_strong_random(&salt_buf, ARGON2_DEFAULT_SALT_LEN))
	{
		elog(ERROR, "cannot generrate random bytes for salt");
	}

	/* Convert binary string to base64 */
	s_ptr = salt_buf;
	for (i = 0; i < ARGON2_DEFAULT_SALT_LEN; i++)
	{
		*s_ptr = _crypt_itoa64[salt_buf[i] & 0x3f];
		s_ptr++;
	}

	/*
	 * Prepare preamble, currently just argon2id is supported.
	 */
	appendStringInfo(result, ARGON2_MAGIC_BYTE_ID);

	/*
	 * Create options string
	 */
	buf = xgen_salt_argon_internal(ARGON2_MAGIC_BYTE_ID,
								   options,
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
	appendStringInfo(result, salt_buf);

	/* and we're done */
	return result;
}

static
text *argon2_internal(const char *pw,
					  const char *salt,
					  int threads,
					  int lanes,
					  int memcost,
					  int rounds,
					  int size,
					  argon2_output_format_t format)
{
	EVP_KDF *ossl_kdf         = NULL;
	EVP_KDF_CTX *ossl_kdf_ctx = NULL;
	unsigned char output[size + 1];
	OSSL_PARAM parameters[7];
	OSSL_PARAM *ptr;

	bytea *result;
	text  *resb64;

	/* Some initialization */
	memset(output, '\0', size + 1);

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
	*ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
											   (void *)salt,
											   strlen ((const char * )salt));
	*ptr++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
											   (void *)pw,
											   strlen ((const char * )pw));
	*ptr++ = OSSL_PARAM_construct_end();

	if ((ossl_kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL)) == NULL)
	{
		goto err;
	}

	if ((ossl_kdf_ctx = EVP_KDF_CTX_new(ossl_kdf)) == NULL)
	{
		goto err;
	}

	if (EVP_KDF_derive(ossl_kdf_ctx, &output[0], size, parameters) != 1)
	{
		goto err;
	}

	/* Seems everything went smooth, prepare the result */

	result = (bytea *) palloc(size + VARHDRSZ);
	SET_VARSIZE(result, size + VARHDRSZ);
	memcpy(VARDATA(result), output, size);

	switch(format)
	{
		case ARGON2_OUTPUT_BASE64:
			resb64 = DatumGetTextP(DirectFunctionCall2(binary_encode,
													   PointerGetDatum(result),
													   PointerGetDatum(cstring_to_text("base64"))));
			break;
		case ARGON2_OUTPUT_HEX:
			resb64 = DatumGetTextP(DirectFunctionCall2(binary_encode,
													   PointerGetDatum(result),
													   PointerGetDatum(cstring_to_text("hex"))));
			break;
	}

	return resb64;

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

	password = PG_GETARG_TEXT_PP(0);
	salt = PG_GETARG_TEXT_PP(1);

	memset(&salt_buf, '\0', ARGON2_SALT_MAX_LEN + 1);
	salt_cstr = text_to_cstring(salt);
	pw_cstr = text_to_cstring(password);

	/* Parse input salt string */
	simple_salt_parser_init(&pinfo, argon2_options, NUM_ARGON2_OPTIONS);
	simple_salt_parser(&pinfo, salt_cstr);

	/* Handle options, if extracted by salt parser */
	if (pinfo.opt_len > 0) {

		if (pinfo.opt_len < 0) {
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
	if (pinfo.salt_len > 0) {
		/*
		 * Theoretically argon2 allows up to (2^32) - 1 bytes of salt length, but
		 * we limit this to a more practical limit.
		 */
		size_t len = Min(pinfo.salt_len, ARGON2_SALT_MAX_LEN);
		memcpy(salt_buf, pinfo.salt, len);

		elog(DEBUG2, "using salt \"%s\"", salt_buf);
	} else {
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string cannot be empty"));
	}

	_argon2_apply_options(options, numoptions,
						  &threads, &lanes, &memcost, &rounds, &size,
						  &output_format, &backend);

	/* Calculate the password hash */
	hash = argon2_internal(pw_cstr,
						   salt_buf,
						   threads,
						   lanes,
						   memcost,
						   rounds,
						   size,
						   output_format);

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
		appendStringInfo(resbuf, "%s%s$%s$%s",
						 ARGON2_MAGIC_BYTE_ID,
						 options_buf,
						 salt_buf,
						 text_to_cstring(hash));
	}
	else
	{
		appendStringInfo(resbuf, "%s%s$%s",
						 ARGON2_MAGIC_BYTE_ID,
						 salt_buf,
						 text_to_cstring(hash));
	}

	result = (text *) palloc(sizeof(resbuf->len) + VARHDRSZ);
	SET_VARSIZE(result, resbuf->len + VARHDRSZ);
	memcpy(VARDATA(result), resbuf->data, resbuf->len);

	PG_RETURN_TEXT_P(result);
}
