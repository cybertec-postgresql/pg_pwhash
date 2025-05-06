

#include "pgxcrypto_yescrypt.h"

#include <utils/builtins.h>

#include "catalog/pg_type_d.h"
#include "fmgr.h"

#define PGXCRYPTO_YESCRYPT_MAX_ROUNDS 11
#define PGXCRYPTO_YESCRYPT_MIN_ROUNDS 1
#define PGXCRYPTO_YESCRYPT_ROUNDS 5

#define NUM_YESCRYPT_OPTIONS 1
static struct pgxcrypto_option yescrypt_options[] =
{
	{ "rounds", "rounds", INT4OID, PGXCRYPTO_YESCRYPT_MIN_ROUNDS,
		PGXCRYPTO_YESCRYPT_MAX_ROUNDS, {._int_value = PGXCRYPTO_YESCRYPT_ROUNDS} }
};

/* ****************************************************************************
 * Forwarded declarations
 * ****************************************************************************/
static void
_yescrypt_apply_options(Datum *options, int num_options, int *rounds);


StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic_string);

PG_FUNCTION_INFO_V1(pxcrypto_yescrypt);

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
				if (strncmp(opt->name, "rounds", strlen(opt->name) == 0)
					&& (strncmp(opt->alias, "rounds", strlen(opt->alias)) == 0))
				{
					*rounds = pg_strtoint32(sep);

					pgxcrypto_check_minmax(opt->min, opt->max, *rounds, opt->alias);
					continue;
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

StringInfo
xgen_salt_yescrypt(Datum *options, int numoptions, const char *magic_string)
{
	StringInfo result;
	int        rounds;

	/* Sanity check: yescrypt requires magic string "$y$" */
	if (magic_string == NULL || strncmp(magic_string, "$y$", 3) != 0)
	{
		ereport(ERROR,
				errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				errmsg("invalid magic string"));
	}

	/* Apply rounds option or default if not specified */
	_yescrypt_apply_options(options, numoptions, &rounds);
}

Datum
pgxcrypto_yescrypt(PG_FUNCTION_ARGS)
{

}