#ifndef PGXCRYPTO_POC_PGXCRYPTO_POC_H
#define PGXCRYPTO_POC_PGXCRYPTO_POC_H

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

struct pgxcrypto_option
{
	char *name;     /* name of the option, as specified by salt function */
	char *alias;    /* alias of the option, as used by the final salt string */
	Oid type;
	int min;
	int max;      /*
 				   * min/max constraint for settings for an option.
 				   * Note the the meaning for this depends on the interpretation
 				   * of the specific option.
 				   */
	union {
		char *_str_value;
		int  _int_value;
	};
};

/*
 * Default buffer size for the algorithm info option string.
 */
#define PGXCRYPTO_ALGO_INFO_LEN 10

struct parse_salt_info
{
	int num_sect;    /* number of parsed sections enclosed by '$' */
	char *salt;      /* direct pointer to salt string */
	size_t salt_len;
	size_t salt_len_min;
	char *magic;     /* direct pointer to magic string */
	size_t magic_len;
	char algo_info[PGXCRYPTO_ALGO_INFO_LEN + 1]; /* info string specific to algorithm. */
	size_t algo_info_len;                        /* length of algo specific string, 0 if not present */
	char *opt_str;   /* direct pointer to options string */
	size_t   opt_len;
	size_t num_parse_options;
	struct pgxcrypto_option *options;
};

void
pgxcrypto_check_minmax(int min, int max, int value, const char *name);

/*
 * Routine to convert binary stringto base64 representation
 */
char *
pgxcrypto_to_base64(const unsigned char *input, int length);

/*
 * Routine to decode a base64 into a binary string.
 */
unsigned char
*pgxcrypto_from_base64(const char *input, int length, int *outlen);

struct pgxcrypto_option
*check_option(const char *key,
			  struct pgxcrypto_option *option,
			  size_t numoptions,
			  bool error_on_mismatch);

void
simple_salt_parser(struct parse_salt_info *pinfo,
				   char * salt);

size_t
makeOptions(char *opt_str, size_t opt_len,
			Datum **options, size_t *num_parsed_opts, size_t num_expected);

/**
 * Returns the current setting for the default argon2 hashing backend.
 */
argon2_digest_backend_t pgxcrypto_get_digest_backend(void);

#endif
