#include "pgxcrypto_yescrypt.h"

#include <crypt.h>
#include <varatt.h>
#include <utils/builtins.h>

#include "catalog/pg_type_d.h"
#include "fmgr.h"

#ifndef _PGXCRYPTO_CRYPT_YESCRYPT_SUPPORT

PG_FUNCTION_INFO_V1(pgxcrypto_yescrypt_crypt);

Datum
pgxcrypto_yescrypt_crypt(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			errmsg("this platform does not provide crypt support for yescrypt"));
}

StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic_string)
{
	ereport(ERROR,
			errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			errmsg("this platform does not provide crypt support for yescrypt"));
}

#else

#define PGXCRYPTO_YESCRYPT_MAX_ROUNDS 11
#define PGXCRYPTO_YESCRYPT_MIN_ROUNDS 1
#define PGXCRYPTO_YESCRYPT_ROUNDS 5

/* magic identifier string for yescrypt */
#define PGXCRYPTO_YESCRYPT_MAGIC "$y$"

/*
 * According to current crypt(5) documentation, there is no lower limit
 * for the length of the salt, but an upper limit.
 *
 * See
 *        Hashed passphrase format
 *        \$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{,86}\$[./A-Za-z0-9]{43}
 */
#define PGXCRYPT_YESCRYPT_CRYPT_MAX_SALT_LEN 86

#define NUM_YESCRYPT_OPTIONS 1
static struct pgxcrypto_option yescrypt_options[] =
{
	{ "rounds", "rounds", INT4OID, PGXCRYPTO_YESCRYPT_MIN_ROUNDS,
		PGXCRYPTO_YESCRYPT_MAX_ROUNDS, {._int_value = PGXCRYPTO_YESCRYPT_ROUNDS} }
};

/* ****************************************************************************
 * Forwarded declarations
 * ****************************************************************************/
StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic_string);

PG_FUNCTION_INFO_V1(pgxcrypto_yescrypt_crypt);

/* ****************************************************************************
 * Implementation
 * ****************************************************************************/
static void
_yescrypt_apply_options(Datum *options, int num_options, int *rounds)
{
	int i;

	*rounds = PGXCRYPTO_YESCRYPT_ROUNDS;

	for (i = 0; i < num_options; i++)
	{
		char *str = TextDatumGetCString(options[i]);

		/* Lookup key/value separator */
		char *sep =strchr(str, '=');

		if (sep)
		{
			struct pgxcrypto_option *opt;

			/* mark position end of key/value pair */
			*sep++ = '\0';
			opt = check_option(str, yescrypt_options, NUM_YESCRYPT_OPTIONS, true);

			if (opt != NULL)
			{
				if (strncmp(opt->name, "rounds", strlen(opt->name)) == 0
					&& strncmp(opt->alias, "rounds", strlen(opt->alias)) == 0)
				{
					*rounds = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min, opt->max, *rounds, opt->alias);
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
}

/**
 * Wrapper function for libc'c crypt_gensalt().
 *
 * @param options Array of options
 * @param numoptions Number of options in array
 * @param magic_string The magic string to recognize
 * @return
 */
StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic_string)
{
	StringInfo result;
	char      *salt_buf;
	int        rounds;

	/* Sanity check: yescrypt requires magic string "$y$" */
	if (magic_string == NULL || strncmp(magic_string,
		PGXCRYPTO_YESCRYPT_MAGIC, strlen(PGXCRYPTO_YESCRYPT_MAGIC)) != 0)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("invalid magic string"));
	}

	/* Apply rounds option or default if not specified */
	_yescrypt_apply_options(options, numoptions, &rounds);

	/* Create the salt */
	result = makeStringInfo();
	salt_buf = crypt_gensalt(PGXCRYPTO_YESCRYPT_MAGIC, rounds, NULL, 0);

	/* Error handling */
	if (errno == EINVAL)
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
}

Datum
pgxcrypto_yescrypt_crypt(PG_FUNCTION_ARGS)
{
	text *password;
	text *salt;
	text *result;
	char *pw_cstr;
	char *salt_str;
	char *hash;

	password = PG_GETARG_TEXT_P(0);
	salt = PG_GETARG_TEXT_P(1);

	if (PG_ARGISNULL(0))
	{
		ereport(ERROR,
			    errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			    errmsg("password argument cannot be NULL"));
	}

	if (PG_ARGISNULL(1))
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("salt string argument cannot be NULL"));
	}

	pw_cstr = text_to_cstring(password);
	salt_str = text_to_cstring(salt);

	/*
	 * Some preliminary checks: salt should start with $y$
	 */
	if (strncmp(salt_str, PGXCRYPTO_YESCRYPT_MAGIC, strlen(PGXCRYPTO_YESCRYPT_MAGIC)) != 0)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("invalid magic string for crypt()"));
	}

	hash = crypt(pw_cstr, salt_str);

	/* Error handling */
	if (errno == EINVAL || hash == NULL)
	{
		char *errm = strerror(errno);
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("error creating password hash with crypt()"),
				errdetail("Internal error using crypt(): %s",
						  errm));
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

	/* Prepare the result */
	result = (text *) palloc(VARHDRSZ + strlen(hash));
	SET_VARSIZE(result, VARHDRSZ + strlen(hash));
	memcpy(VARDATA(result), hash, strlen(hash));

	/* ... and we're done */
	PG_RETURN_TEXT_P(result);
}

#endif

Datum
xcrypt_yescrypt_crypt(Datum password, Datum salt)
{
	return DirectFunctionCall2(pgxcrypto_yescrypt_crypt, password, salt);
}
