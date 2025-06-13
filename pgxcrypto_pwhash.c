#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_type_d.h"
#include "utils/builtins.h"
#include "utils/array.h"
#include "utils/guc.h"
#include "openssl/evp.h"

#include "pgxcrypto_pwhash.h"
#include "pgxcrypto_scrypt.h"
#include "pgxcrypto_argon2.h"
#include "pgxcrypto_yescrypt.h"

PG_FUNCTION_INFO_V1(pgxcrypto_test_options);
PG_FUNCTION_INFO_V1(xgen_salt);
PG_FUNCTION_INFO_V1(pgxcrypt_crypt);
PG_FUNCTION_INFO_V1(xcrypt);


/**
 * Enables/disable padding of base64 encoded strings.
 */
static bool pgxcrypto_setting_always_pad_base64 = false;

/**
 * Default argon2 backend to use for hashing.
 */
static int argon2_backend = ARGON2_BACKEND_TYPE_OSSL;

struct pgxcrypto_magic
{
  char *name;
  char *magic;
  StringInfo (*gen) (Datum *, int, const char *);
  Datum (*crypt) (Datum pw, Datum salt);
};

static struct pgxcrypto_magic pgxcrypto_algo[] =
{
	{ "scrypt", "$scrypt$", xgen_salt_scrypt, xcrypt_scrypt },
	{ "$7$", "$7$", xgen_crypt_gensalt_scrypt, xcrypt_scrypt_crypt },
	{ "argon2id", "$argon2id$", xgen_salt_argon2, xcrypt_argon2 },
	{ "argon2d", "$argon2d$", xgen_salt_argon2, xcrypt_argon2 },
	{ "argon2i", "$argon2i$", xgen_salt_argon2, xcrypt_argon2 },
	{ "yescrypt", "$y$", xgen_salt_yescrypt, xcrypt_yescrypt_crypt },
	{ NULL, NULL, NULL }
};

static const struct config_enum_entry pgxcrypto_argon2_backend_option[] = {
	{ "openssl", ARGON2_BACKEND_TYPE_OSSL, false },
	{ "libargon2", ARGON2_BACKEND_TYPE_LIBARGON2, false },
	{ NULL, 0, false }
};

/*
 * Unpads a given base64 string.
 *
 * Does its work inplace, thus not replacing the input buffer. Padding is
 * replaced by null bytes.
 */
static char *
pgxcrypto_unpad_base64(char *input, int len, int *unpad_len)
{
	char *s_ptr;

	*unpad_len = len;

	/* position before last null byte */
	s_ptr = input + (len - 1);

	while (*s_ptr == '=') {
		*s_ptr = '\0';
		s_ptr--;
	}

	return input;
}

/*
 * Pads the base64 input if required.
 *
 * The caller is responsible to make sure that buffers checks compatible
 * base64 characters.
 *
 * This routine strictly just operates on the length of the input buffer. If
 * the length is modulo 4, it returns input, so the result points to the same
 * input buffer and nothing is modified within the content of input.
 *
 * Otherwise a palloc'ed buffer is returned with padded '=' at the end.
 */
static char *
pgxcrypto_pad_base64(const char *input, int length, int *pd_len)
{
	int   pads = ( 4 - (length % 4) );
	char *padded;

	/* Fast path if no padding required */
	if (pads == 4)
	{
		*pd_len = length;
		return (char *)input;
	}

	*pd_len = length + pads;
	padded = palloc0(*pd_len + 1);
	memcpy(padded, input, length);
	memset(padded + length, '=', sizeof(char) * pads );

	return padded;
}

/*
 * Check specified lower and upper bound against value.
 *
 * Will ereport an ERROR in case value exceeds either one of them.
 */
void
pgxcrypto_check_minmax(int min, int max, int value, const char *param_name)
{
	if (value < min)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("%s \"%d\" cannot be lower than \"%d\"",
					   param_name, value, min));
	}

	if (value > max)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("%s \"%d\" cannot be larger than \"%d\"",
					   param_name, value, max));
	}
}

/*
 * Returns a base64 (PEM) encoded string representation of input. The output
 * character array is palloc'ed and initialized with NULL bytes. If the output
 * cannot be converted correctly, this function elog's an ERROR and thus
 * doesn't return.
 */
char *pgxcrypto_to_base64(const unsigned char *input, int length)
{
	const int pl = 4*((length+2)/3);
	char *output = (char *)palloc0(pl+1); /* +1 for the terminating null that EVP_EncodeBlock adds */
	const int ol = EVP_EncodeBlock((unsigned char *)output, input, length);
	int unpd_len;

	if (ol != pl)
	{
		elog(ERROR, "base64 encode predicted \"%d\" but we got \"%d\"", pl, ol);
	}

	/*
	 * EVP_EncodeBlock() always pads, check if we have to deal with it.
	 */
	if (pgxcrypto_setting_always_pad_base64)
	{
		return output;
	}

	/* In case padding is not requested */
	return pgxcrypto_unpad_base64(output, (int)strlen(output), &unpd_len);
}

/*
 * Returns a decoded representation of the base64 encoded input. If the input
 * cannot properly decoded, this function elog's an ERROR and doesn't return.
 *
 * Please note that short base64 input (thus input which is not properly
 * padded), will implicitly padded before decoding. pgxcrypto always pads
 * output, but we also need to cooperate with external resources which might not.
 *
 * outlen stores the number of 3 byte blocks decoded by OpenSSLs'
 * EVP_DecodeBlock() and doesn't reflect the real number of bytes contained in
 * the returned buffer!
 */
unsigned char *pgxcrypto_from_base64(const char *input, int length, int *outlen)
{
	int            pd_len = length; /* padded length */
	int            ol;
	char          *padded;
	unsigned char *output;

	/* Pad input if necessary */
	padded = pgxcrypto_pad_base64(input, length, &pd_len);
	ol = 3 * pd_len / 4;
	output = (unsigned char *) palloc0(ol + 1); /* +1 null byte */

	*outlen = EVP_DecodeBlock(output, (unsigned char *)padded, pd_len);

	if ((*outlen) != ol)
	{
		elog(ERROR, "decode predicted \"%d\" but we got \"%d\"", (*outlen), ol);

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

		if ((strncmp(key, option.name, strlen(option.name)) == 0)
			|| (strncmp(key, option.alias, strlen(option.alias)) == 0))
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
 *
 * This parser instance doesn't extract optional specifications
 * for algorithms. E.g. Argon2 usually have since v1.3 of the Argon2
 * implementation an additional section after the magic bytes which references
 * the used Argon2 version and this isn't present before.
 * We don't inspect this here, instead focus on parsing the ...options...
 * and salt part of the salt string.
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
	/*
	 * Iff the salt wasn't closed with a trailing '$', we might have parsed the salt, but
	 * not yet set the final length of it. So do it here at the final step of the parser.
	 */
	else if (pinfo->salt_len == 0)
	{
		pinfo->salt_len = strlen(pinfo->salt);
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
xcrypt(PG_FUNCTION_ARGS)
{
	text *salt     = PG_GETARG_TEXT_PP(1);
	struct pgxcrypto_magic *algo;
	char *salt_cstr;

	if (PG_ARGISNULL(0))
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("password cannot be NULL"));
	}

	if (PG_ARGISNULL(1))
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string cannot be NULL"));
	}

	salt_cstr = text_to_cstring(salt);

	/*
	 * Salt string should have magic byte and a length of at least 3 bytes, otherwise
	 * it is meaningless
	 */
	if (strlen(salt_cstr) < 3)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string too short"));
	}

	/*
	 * Loop through available algorithms and check if we have a function
	 * available identified by the magic string
	 */
	algo = pgxcrypto_algo;

	while (algo->magic != NULL)
	{
		if (strncmp(algo->magic, salt_cstr, strlen(algo->magic)) == 0)
		{
			elog(DEBUG2, "magic salt %s", algo->magic);
			PG_RETURN_DATUM(algo->crypt(PG_GETARG_DATUM(0), PG_GETARG_DATUM(1)));
		}

		algo++;
	}

	/* If we land here, no suitable algorithm was found */
	ereport(ERROR,
			errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			errmsg("could not determine algorithm from given salt string"));
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
	magic = pgxcrypto_algo;

	while (magic->name != NULL)
	{
		if (strncmp(magic->name, crypt_name, strlen(magic->name)) == 0)
		{
			/* call the crypto salt function */
			if (magic->gen != NULL)
				salt = magic->gen(options, noptions, magic->magic);
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
		elog(ERROR, "cannot create a valid salt string for hash method \"%s\"",
			 crypt_name);
	}

	/* Prepare the final salt string */
	result = (text *)palloc(salt->len + VARHDRSZ);
	SET_VARSIZE(result, salt->len + VARHDRSZ);
	memcpy(VARDATA(result), salt->data, salt->len);

	destroyStringInfo(salt);
	PG_RETURN_TEXT_P(result);
}

argon2_digest_backend_t pgxcrypto_get_digest_backend(void)
{
	return argon2_backend;
}

void
_PG_init(void)
{
	DefineCustomEnumVariable("pgxcrypto.argon2_default_backend",
						 "Selects the default backend to use for argon2 hashing",
						 NULL,
						 &argon2_backend,
						 ARGON2_BACKEND_TYPE_OSSL,
						 pgxcrypto_argon2_backend_option,
						 PGC_USERSET,
						 0,
						 NULL,
						 NULL,
						 NULL);

	DefineCustomBoolVariable("pgxcrypto.always_pad_base64",
							 "Forces base64 output to be padded, the default is on",
							 NULL,
							 &pgxcrypto_setting_always_pad_base64,
							 false,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);


}