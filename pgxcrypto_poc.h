#ifndef PGXCRYPTO_POC_PGXCRYPTO_POC_H
#define PGXCRYPTO_POC_PGXCRYPTO_POC_H

struct pgxcrypto_option
{
  char *name;
  Oid type;
  union {
	char *_str_value;
	int _int_value;
  };
};

struct parse_salt_info
{

  int num_sect;    /* number of parsed sections enclosed by '$' */
  char *salt;      /* direct pointer to salt string */
  char *pw;        /* direct pointer to password string */
  size_t salt_len;
  size_t salt_len_min;
  char *magic;     /* direct pointer to magic string */
  size_t magic_len;
  char *opt_str;   /* direct pointer to options string */
  size_t   opt_len;
  size_t num_parse_options;
  struct pgxcrypto_option *options;

};

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

#endif
