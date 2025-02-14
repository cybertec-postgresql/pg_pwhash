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

#define ARGON2_MAGIC_BYTE "$argon2d$"

/*
 * Recommended tag length is at least 128 bits, but
 *
 * https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/#description
 *
 * suggests 128 Byte of output length, so we use this.
 */
#define ARGON2_HASH_LEN 128

PG_FUNCTION_INFO_V1(pgxcrypto_argon2);

/* Base64 lookup table */
static unsigned char _crypt_itoa64[64 + 1] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Keep that in sync with below options array */
#define NUM_ARGON2_OPTIONS 4

struct pgxcrypto_option argon2_options[] =
{
		{ "threads", INT4OID, { ._int_value = ARGON2_THREADS } },
		{ "lanes", INT4OID, { ._int_value = ARGON2_MEMORY_LANES } },
		{ "memcost", INT4OID, { ._int_value = ARGON2_MEMORY_COST } },
		{ "rounds", INT4OID, { ._int_value = ARGON2_ROUNDS } }
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
						   int   *rounds);

/* *********************** Implementation *********************** */

static
void _argon2_apply_options(Datum *options,
						   size_t numoptions,
						   int   *threads,
						   int   *lanes,
						   int   *memory_cost,
						   int   *rounds)
{
	int i;

	/* Set defaults first */
	*threads     = ARGON2_THREADS;
	*lanes       = ARGON2_MEMORY_LANES;
	*memory_cost = ARGON2_MEMORY_COST;
	*rounds      = ARGON2_ROUNDS;

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
				if (strncmp(opt->name, "threads", strlen(opt->name)) == 0)
				{
					*threads = pg_strtoint32(sep);
					continue;
				}

				if (strncmp(opt->name, "lanes", strlen(opt->name)) == 0)
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
			}

		}
	}
}

static
void simple_salt_parser_init(struct parse_salt_info *pinfo,
							 struct pgxcrypto_option *options,
							 size_t numoptions)
{
	pinfo->magic        = (char *)ARGON2_MAGIC_BYTE;
	pinfo->magic_len    = strlen(pinfo->magic);
	pinfo->salt_len_min = ARGON2_SALT_MAX_LEN / 4;
	pinfo->salt         = NULL;
	pinfo->opt_str      = NULL;
	pinfo->num_sect     = 0;
	pinfo->opt_len      = 0;
	pinfo->options      = options;
	pinfo->num_parse_options = numoptions;
}

static
text *argon2_internal(const char *pw,
					  const char *salt,
					  int threads,
					  int lanes,
					  int memcost,
					  int rounds)
{
	EVP_KDF *ossl_kdf         = NULL;
	EVP_KDF_CTX *ossl_kdf_ctx = NULL;
	unsigned char output[ARGON2_HASH_LEN + 1];
	OSSL_PARAM parameters[7];
	OSSL_PARAM *ptr;

	bytea *result;
	text  *resb64;

	/* Some initialization */
	memset(output, '\0', ARGON2_HASH_LEN + 1);

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

	if ((ossl_kdf = EVP_KDF_fetch(NULL, "ARGON2D", NULL)) == NULL)
	{
		goto err;
	}

	if ((ossl_kdf_ctx = EVP_KDF_CTX_new(ossl_kdf)) == NULL)
	{
		goto err;
	}

	if (EVP_KDF_derive(ossl_kdf_ctx, &output[0], ARGON2_HASH_LEN, parameters) != 1)
	{
		goto err;
	}

	/* Seems everything went smooth, prepare the result */

	result = (bytea *) palloc(ARGON2_HASH_LEN + VARHDRSZ);
	SET_VARSIZE(result, ARGON2_HASH_LEN + VARHDRSZ);
	memcpy(VARDATA(result), output, ARGON2_HASH_LEN);

	resb64 = DatumGetTextP(DirectFunctionCall2(binary_encode,
											   PointerGetDatum(result),
											   PointerGetDatum(cstring_to_text("base64"))));

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
	Datum       *options      = NULL;
	size_t       numoptions   = 0;

	char *options_buf = NULL;

	struct parse_salt_info pinfo;

	char salt_buf[ARGON2_SALT_MAX_LEN + 1];

	text *password;
	text *salt;
	char *salt_cstr;

	/* Argon2 parameters for hash generation */
	int threads;
	int lanes;
	int memcost;
	int rounds;

	password = PG_GETARG_TEXT_PP(0);
	salt     = PG_GETARG_TEXT_PP(1);

	memset(&salt_buf , '\0', ARGON2_SALT_MAX_LEN + 1);
	salt_cstr = text_to_cstring(salt);

	/* Parse input salt string */
	simple_salt_parser_init(&pinfo, argon2_options, NUM_ARGON2_OPTIONS);
	simple_salt_parser(&pinfo, salt_cstr);

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

	_argon2_apply_options(options, numoptions,
						  &threads, &lanes, &memcost, &rounds);

	PG_RETURN_TEXT_P(argon2_internal(text_to_cstring(password),
						   salt_buf,
						   threads,
						   lanes,
						   memcost,
						   rounds));
}
