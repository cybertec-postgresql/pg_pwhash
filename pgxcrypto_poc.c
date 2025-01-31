#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_type_d.h"
#include "nodes/parsenodes.h"
#include "utils/builtins.h"
#include "utils/array.h"

#include "pgxcrypto_poc.h"

PG_FUNCTION_INFO_V1(pgxcrypto_test_options);

static bool check_options(const char *key,
						  struct pgxcrypto_option *options,
						  int numoptions)
{
	int i;

	if (options == NULL)
	{
		elog(ERROR, "cannot evaluate crypto options");
	}

	for (i = 0; i < numoptions; i++) {

		struct pgxcrypto_option option = options[i];

		if (strncmp(key, option.name, strlen(key)))
		{
			return true;
		}
	}
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
	Node  *value;
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

		elog(NOTICE, "got option string key=\"%s\"/value=\"%s\"", str, sep);
	}

	PG_RETURN_VOID();

}