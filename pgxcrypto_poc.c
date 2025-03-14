#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "utils/array.h"
#include "openssl/evp.h"

#include "pgxcrypto_poc.h"
#include "pgxcrypto_scrypt.h"
#include "pgxcrypto_argon2.h"

PG_FUNCTION_INFO_V1(pgxcrypto_test_options);
PG_FUNCTION_INFO_V1(xgen_salt);
PG_FUNCTION_INFO_V1(pgxcrypt_crypt);

struct pgxcrypto_magic
{
  char *name;
  char *magic;
  StringInfo (*gen) (Datum *, int);
};

static struct pgxcrypto_magic pgxcrpyto_algo[] =
{
	{ "scrypt", "$7$", xgen_salt_scrypt },
	{ "argon2id", "$argon2id$", xgen_salt_argon2id },
	{ NULL, NULL, NULL }
};


char *pgxcrypto_to_base64(const unsigned char *input, int length)
{
	const int pl = 4*((length+2)/3);
	char *output = (char *)palloc0(pl+1); /* +1 for the terminating null that EVP_EncodeBlock adds */
	const int ol = EVP_EncodeBlock((unsigned char *)output, input, length);

	if (ol != pl)
	{
		elog(ERROR, "base64 encode predicted \"%d\" but we got \"%d\"", pl, ol);
	}

	return output;
}

unsigned char *pgxcrypto_from_base64(const char *input, int length)
{
	const int pl = 3*length/4;
	unsigned char *output = (unsigned char *) palloc0(pl+1); /* +1 null byte */
	const int ol = EVP_DecodeBlock(output, (unsigned char *)input, length);

	if (pl != ol)
	{
		elog(ERROR, "decode predicted \"%d\" but we got \"%d\"", pl, ol);

	}

	return output;
}

struct pgxcrypto_option * check_option(const char *key,
									   struct pgxcrypto_option *options,
									   size_t numoptions,
									   bool error_on_mismatch)
{
	int i;

	if (options == NULL)
	{
		elog(ERROR, "cannot evaluate crypto options");
	}

	for (i = 0; i < numoptions; i++) {

		struct pgxcrypto_option option = options[i];

		if ((strncmp(key, option.name, strlen(key)) == 0)
			|| (strncmp(key, option.alias, strlen(key)) == 0))
		{
			return &options[i];
		}

	}

	/* If no matching key, error out if requested */
	if (error_on_mismatch)
		elog(ERROR, "invalid option name: \"%s\"", key);

	return NULL;
}

/*
 * Examine structure of the specified salt. We expect at least
 * something in the format
 *
 * $id$[...algorithm specific...]$[...options...$]salt[$password hash]
 *
 * Check if the magic bytes confirms what we expect.
 *
 * Then look for '$' first and check if it has the expected
 * sections.
 */
void
simple_salt_parser(struct parse_salt_info *pinfo,
				   char *salt)
{
	char *s_ptr     = NULL;
	size_t salt_len = strlen(salt);

	if (salt == NULL)
		elog(ERROR, "cannot parse undefined salt string");

	s_ptr = salt;

	/* Salt len must exceed magic byte len + salt len */
	if (salt_len < pinfo->salt_len_min + pinfo->magic_len)
	{
		elog(ERROR, "invalid salt string");
	}

	/*
	 * Check magic byte
	 */
	if (strncmp(salt, pinfo->magic, pinfo->magic_len) != 0)
	{
		elog(ERROR, "invalid magic byte in salt preamble, expected \"%s\"",
			 pinfo->magic);
	}

	s_ptr       = salt + pinfo->magic_len;

	/*
	 * Check optional magic components. E.g. Argon2 hashes can have the used
	 * Argon2 version preamble directly after the magic bytes, so make sure we
	 * skip them correctly, if present. The caller is responsible to handle this
	 * specific information itself.
	 */
	if (pinfo->algo_info_len > 0)
	{
		s_ptr += pinfo->algo_info_len;
	}

	/*
 	 * Parse input for '$' restrictions.
 	 */
	pinfo->salt = s_ptr;

	while (*s_ptr != '\0')
	{
		if (*s_ptr == '$')
		{
			if (pinfo->num_sect == 0)
			{
				/*
				 * First section delimiter encountered, treat this as option
				 * string.
				 */
				pinfo->opt_str = pinfo->salt;
				pinfo->opt_len = s_ptr - (pinfo->salt);

				/*
				 * We haven't reached the end of the string yet, the next
				 * section should be the salt so move the pointer to the
				 * salt section one byte forward than the current position.
				 */
				pinfo->salt    = s_ptr + 1;

			}

			if (pinfo->num_sect == 1)
			{
				/*
				 * We've already parsed a section before which must be the
				 * one for the options string. This here marks the end of the
				 * salt.
				 */
				pinfo->salt_len = s_ptr - pinfo->salt;
			}

			pinfo->num_sect++;
		}

		s_ptr++;
	}

	/*
	 * If we've parsed more than required section identifiers we treat this
	 * as an error
	 */
	if (pinfo->num_sect > 2)
	{
		elog(ERROR, "invalid number of sections in salt string, expected up to two, got %d",
			 pinfo->num_sect);
	}

	if (pinfo->salt == NULL)
	{
		/*
		 * We haven't parsed any section, treat the whole string as an input
		 * salt.
		 */
		pinfo->salt = salt + pinfo->magic_len;
		pinfo->salt_len = s_ptr - (pinfo->salt);
	}

}

/*
 * Takes a string with comma separated options and creates an array with
 * text datums.
 */
size_t
makeOptions(char *opt_str, size_t opt_len,
			Datum **options, size_t *num_parsed_opts, size_t num_expected)
{
	char *s_ptr = opt_str;
	char *e_ptr = opt_str;

	/* Init */
	*num_parsed_opts = 0;
	*options        = 0;

	/* Sanity checks */
	if (opt_str == NULL)
	{
		elog(ERROR, "options cannot be undefined");
	}

	if (opt_len <= 0) {
		return *num_parsed_opts;
	}

	if (num_expected <= 0)
	{
		elog(ERROR, "number of expected options can't be zero");
	}

	*options = (Datum *) palloc(sizeof(Datum) * num_expected);

	while (*e_ptr != '\0')
	{
		if (*e_ptr == ',')
		{
			size_t len = 0;
			text  *tval;

			len = e_ptr - s_ptr;

			tval = (text *) palloc(len + VARHDRSZ);
			SET_VARSIZE(tval, len + VARHDRSZ);
			memcpy(VARDATA(tval), s_ptr, len);

			(*options)[(*num_parsed_opts)++] = PointerGetDatum(tval);
			elog(DEBUG2, "extracted %s, len %lu", text_to_cstring(tval), len);

			/* Safe, since there must be at least the null byte */
			s_ptr = e_ptr + 1;

			/* len must be >= 0 */
			if (len <= 0)
			{
				elog(DEBUG2, "option string length cannot be zero");
			}
		}

		e_ptr++;
	}

	/*
	 * All remaining bytes, also in case there was just one argument
	 * given
	 */
	if (e_ptr > s_ptr)
	{
		size_t len = 0;
		text  *tval;

		len = e_ptr - s_ptr;

		if (len <= 0)
		{
			elog(ERROR, "option string length cannot be zero");
		}

		tval = (text *) palloc(len + VARHDRSZ);
		SET_VARSIZE(tval, len + VARHDRSZ);
		memcpy(VARDATA(tval), s_ptr, len);

		(*options)[(*num_parsed_opts)++] = PointerGetDatum(tval);

		elog(DEBUG2, "extracted %s, len %lu", text_to_cstring(tval), len);
	}

	return *num_parsed_opts;
}

/*
 * Evaluates an options array.
 */
Datum
pgxcrypto_test_options(PG_FUNCTION_ARGS)
{
	Datum arg = PG_GETARG_DATUM(0);
	ArrayType *array = DatumGetArrayTypeP(arg);
	Datum *options;
	int    noptions;
	int    i;

	deconstruct_array_builtin(array, TEXTOID, &options, NULL, &noptions);

	for (i = 0; i < noptions; i++)
	{
		char *str = TextDatumGetCString(options[i]);

		/* Lookup Key=Value separator */
		char *sep = strchr(str, '=');

		if (sep)
		{
			*sep++ = '\0';

		}

		elog(DEBUG2, "got option string key=\"%s\"/value=\"%s\"", str, sep);
	}

	PG_RETURN_VOID();

}

Datum
xgen_salt(PG_FUNCTION_ARGS)
{
	text *crypt_opt      = PG_GETARG_TEXT_PP(0);
	Datum argoptions     = PG_GETARG_DATUM(1);
	ArrayType *optarray  = DatumGetArrayTypeP(argoptions);
	char      *crypt_name         = text_to_cstring(crypt_opt);
	StringInfo salt               = NULL;
	struct pgxcrypto_magic *magic = NULL;

	int    noptions;
	Datum *options;
	text  *result;

	/* Construct array */
	deconstruct_array_builtin(optarray, TEXTOID, &options, NULL, &noptions);

	/*
	 * First argument is the requested algorithm
	 */
	magic = pgxcrpyto_algo;

	while (magic->name != NULL)
	{
		if (strncmp(magic->name, crypt_name, strlen(crypt_name)) == 0)
		{
			/* call the crypto salt function */
			if (magic->gen != NULL)
				salt = magic->gen(options, noptions);
			else
				elog(ERROR, "requested hash has no salt generator");

			/* no need to look further */
			break;
		}

		magic++;
	}

	/* If salt is still undefined we treat this as an error */
	if (salt == NULL)
	{
		elog(ERROR, "cannot create a valid salt string");
	}

	/* Prepare the final salt string */
	result = (text *)palloc(salt->len + VARHDRSZ);
	SET_VARSIZE(result, salt->len + VARHDRSZ);
	memcpy(VARDATA(result), salt->data, salt->len);

	destroyStringInfo(salt);
	PG_RETURN_TEXT_P(result);
}