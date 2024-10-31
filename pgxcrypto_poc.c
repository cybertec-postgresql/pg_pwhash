/*
 * sha256crypt() and sha512crypt() implementation
 *
 * Algorithm adapted from Ulrich Drepper:
 *
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 *
 * Note: Code is public domain
 *
 * Adapted for PostgreSQL.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "varatt.h"

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

PG_MODULE_MAGIC;

/* Maximum salt string length.  */
#define SHACRYPT_SALT_LEN_MAX 16

/* Default number of rounds if not explicitly specified.  */
#define SHACRYPT_ROUNDS_DEFAULT 5000

/* Minimum number of rounds.  */
#define SHACRYPT_ROUNDS_MIN 1000

/* Maximum number of rounds.  */
#define SHACRYPT_ROUNDS_MAX 999999999

/* SHA buffer length */
#define SHACRYPT_DIGEST_MAX_LENGTH 64

static const unsigned char cov_2char[64] = {
		/* from crypto/des/fcrypt.c */
		0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
		0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
		0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
		0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
		0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
		0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
		0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
		0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A
};

static const char ascii_dollar[] = { 0x24, 0x00 };

typedef enum {
  PGCRYPTO_SHA256CRYPT = 0,
  PGCRYPTO_SHA512CRYPT = 1,
  PGCRYPTO_SHA_UNKOWN
} PGCRYPTO_SHA_t;

PG_FUNCTION_INFO_V1(pg_sha_gensalt);
PG_FUNCTION_INFO_V1(pg_shacrypt);

Datum
pg_sha_gensalt(PG_FUNCTION_ARGS)
{
	static const char sha256_prefix[4] = "$5$";
	static const char sha512_prefix[4] = "$6$";
	static const char rounds_prefix[]  = "rounds=";
	unsigned int result_bufsize
		= 3                       /* $x$ */
		+ strlen(rounds_prefix)   /* $x$rounds= */
		+ 10                      /* $x$rounds=9999... */
		+ 1                       /* $x$rounds=9999...$ */
		+ SHACRYPT_SALT_LEN_MAX   /* $x$rounds=9999...$...salt... */
		+ 1;                      /* null byte */

	/* sha{256|512}crypt expects a 16 byte salt string */
	char salt_string[SHACRYPT_SALT_LEN_MAX + 1];

	/* 1st argument is the encryption type */
	int rounds     = SHACRYPT_ROUNDS_DEFAULT;
	char *sha_algo;
	PGCRYPTO_SHA_t type = PGCRYPTO_SHA_UNKOWN;
	char *result;
	char *sp;

	/* converted string representation for 2nd arg */
	char rounds_string[11];

	/* Initializing */
	memset(&salt_string, '\0', SHACRYPT_SALT_LEN_MAX + 1);
	memset(&rounds_string, '\0', 11);

	/* Be paranoid and check NULL arguments */
	if (!PG_ARGISNULL(0))
	{
		sha_algo = text_to_cstring(PG_GETARG_TEXT_PP(0));
	}
	else
	{
		elog(ERROR, "first argument must be either \"sha256crypt\" or \"sha512crypt\"");
	}

	/* Check hash identifier, 1st argument */
	if (strncmp(sha_algo, "sha256crypt", strlen(sha_algo)) == 0)
	{
		type = PGCRYPTO_SHA256CRYPT;
	}

	if (strncmp(sha_algo, "sha512crypt", strlen(sha_algo)) == 0)
	{
		type = PGCRYPTO_SHA512CRYPT;
	}

	if (type == PGCRYPTO_SHA_UNKOWN)
	{
		elog(ERROR, "unknown sha crypt identifier \"%s\"", sha_algo);
	}

	if (!PG_ARGISNULL(1)) {

		/* 2nd argument is optional and defines the number of iterations */
		rounds = DatumGetInt32(PG_GETARG_INT32(1));

	}

	pg_snprintf(rounds_string, 10, "%d", rounds);

	/*
	 * Make sure we don't overwrite expected size
	 * of rounds string representation
	 */
	Assert(strlen(rounds_string) < 10);

	if (!pg_strong_random(salt_string, SHACRYPT_SALT_LEN_MAX))
	{
		elog(ERROR, "error generating random bytes for salt");
	}

	for (int i = 0; i < SHACRYPT_SALT_LEN_MAX; i++)
	{
		(salt_string)[i] = cov_2char[salt_string[i] & 0x3f];
	}

	/* prepare output */
	result = (char *) palloc0(result_bufsize);
	sp = result;

	switch(type)
	{
		case PGCRYPTO_SHA256CRYPT:
		{
			strlcat(sp, sha256_prefix, result_bufsize);
			break;
		}

		case PGCRYPTO_SHA512CRYPT:
		{
			strlcat(sp, sha512_prefix, result_bufsize);
			break;
		}

		default:
			/* we should not end here, but handle it for safety anyways */
			elog(ERROR, "unknown sha crypt identifier \"%s\"", sha_algo);
	}

	sp += 3;
	strlcat(sp, rounds_prefix, result_bufsize);
	sp += strlen(rounds_prefix);
	strlcat(sp, rounds_string, result_bufsize);
	sp += strlen(rounds_string);
	strlcat(sp, "$", result_bufsize);
	sp += 1;
	strlcat(sp, salt_string, result_bufsize);

	PG_RETURN_TEXT_P(cstring_to_text(result));
}

Datum
pg_shacrypt(PG_FUNCTION_ARGS)
{
	static const char rounds_prefix[] = "rounds=";
	static char *magic_bytes[2] = { "$5$", "$6$" };
	/* "$6$rounds=<N>$......salt......$...shahash(up to 86 chars)...\0" */
	char out_buf[3 + 17 + 17 + 86 + 1]; /* resulting encrypted password buffer */

	PGCRYPTO_SHA_t type = PGCRYPTO_SHA_UNKOWN;
	const EVP_MD  *sha  = NULL;
	EVP_MD_CTX *digestA;
	EVP_MD_CTX *digestB;

	text *password; /* password to encrypt */

	text *salt;     /* user provided salt or generated one */
	char *salt_binary; /* complete salt string as char */
	char *dec_salt_binary; /* pointer into the real salt string */
	char *passwd_binary; /* password string as char */

	unsigned char sha_buf[SHACRYPT_DIGEST_MAX_LENGTH];
	unsigned char sha_buf_tmp[SHACRYPT_DIGEST_MAX_LENGTH]; /* temporary buffer for digests */

	char rounds_custom = 0;
	char *p_bytes = NULL;
	char *s_bytes = NULL;
	char *cp = NULL;

	size_t buf_size = 0;  /* default for sha256crypt */
	unsigned int block;         /* number of bytes processed */
	unsigned int rounds = SHACRYPT_ROUNDS_DEFAULT;

	text *ret; /* return value with hashed password */
	unsigned len, salt_len;

	/* Some sanity checks */
	if (PG_ARGISNULL(0))
	{
		elog(ERROR, "null value for password string not allowed");
	}

	memset(&out_buf, '\0', sizeof(out_buf));

	/* Get password string from argument */
	password = PG_GETARG_TEXT_PP(0);
	passwd_binary = text_to_cstring(password);
	len           = strlen(passwd_binary);

	if (!PG_ARGISNULL(1))
	{
		char *ep; /* holds pointer to the end of the salt string */

		/*
		 * Get the salt string from argument.
		 */
		salt = PG_GETARG_TEXT_PP(1);
		salt_len = VARSIZE_ANY_EXHDR(salt);
		salt_binary = text_to_cstring(salt);

		dec_salt_binary = salt_binary;

		/*
		 * Analyze and prepare the salt string
		 *
		 * The magic string should be specified in the first three bytes
		 * of the salt string. But do some sanity checks before.
		 */
		if (strlen(salt_binary) < 3)
		{
			elog(ERROR, "invalid salt");
		}

		/*
         * Check format of magic bytes. These should define either
         * 5=sha256crypt or 6=sha512crypt in the second byte, enclosed by
         * ascii dollar signs.
         */
		if ((dec_salt_binary[0] != ascii_dollar[0])
		    && (dec_salt_binary[2] != ascii_dollar[0]))
		{
			elog(ERROR, "invalid format of salt");
		}

		if (strncmp(salt_binary, magic_bytes[0], strlen(magic_bytes[0])) == 0)
		{
			type = PGCRYPTO_SHA256CRYPT;
			dec_salt_binary += strlen(magic_bytes[0]);
		}

		if (strncmp(salt_binary, magic_bytes[1], strlen(magic_bytes[1])) == 0)
		{
			type = PGCRYPTO_SHA512CRYPT;
			dec_salt_binary += strlen(magic_bytes[1]);
		}

		/* sp pointer is positioned after the magic bytes now */
		if (strncmp(dec_salt_binary,
					rounds_prefix, sizeof(rounds_prefix) - 1) == 0) {

			const char *num = dec_salt_binary + sizeof(rounds_prefix) - 1;
			char *endp;
			unsigned long int srounds = strtoul (num, &endp, 10);
			if (*endp == '$') {
				dec_salt_binary = endp + 1;
				if (srounds > SHACRYPT_ROUNDS_MAX)
					rounds = SHACRYPT_ROUNDS_MAX;
				else if (srounds < SHACRYPT_ROUNDS_MIN)
					rounds = SHACRYPT_ROUNDS_MIN;
				else
					rounds = (unsigned int)srounds;
				rounds_custom = 1;
			} else {
				PG_RETURN_NULL();
			}

		}

		/*
		 * We need the real length of the decoded salt string, this is every
		 * character after the last '$' in the preamble.
		 */
		for (ep = dec_salt_binary;
			*ep && *ep != '$' && ep < (dec_salt_binary + SHACRYPT_SALT_LEN_MAX);
			ep++) continue;

		salt_len = ep - dec_salt_binary;

		elog(NOTICE, "using rounds = %d", rounds);
		/* unknown magic byte handled below */

	}
	else
	{

		elog(ERROR, "null value for salt string not allowed");

	}

	/*
	 * Choose the correct digest length and add the magic bytes to
	 * the result buffer.
	 */
	switch(type)
	{
		case PGCRYPTO_SHA256CRYPT:
		{
			sha = EVP_sha256();
			buf_size = 32;

			elog(NOTICE,
				 "using sha256crypt as requested by magic byte in salt");
			strlcat(out_buf, magic_bytes[0], sizeof(out_buf));
			break;
		}

		case PGCRYPTO_SHA512CRYPT:
		{
			sha = EVP_sha512();
			buf_size = SHACRYPT_DIGEST_MAX_LENGTH;

			elog(NOTICE,
				 "using sha512crypt as requested by magic byte in salt");
			strlcat(out_buf, magic_bytes[1], sizeof(out_buf));
			break;
		}

		case PGCRYPTO_SHA_UNKOWN:
			elog(ERROR, "unknown crypt identifier \"%c\"", salt_binary[1]);
	}

	if (rounds_custom > 0)
	{

		char tmp_buf[80]; /* "rounds=999999999" */

		snprintf(tmp_buf, sizeof(tmp_buf), "rounds=%u", rounds);
		strlcat(out_buf, tmp_buf, sizeof(out_buf));
		strlcat(out_buf, ascii_dollar, sizeof(out_buf));

	}

	strlcat(out_buf, dec_salt_binary, sizeof(out_buf));

	if (strlen(out_buf) > 3 + 17 * rounds_custom + salt_len)
	{
		elog(ERROR, "invalid salt string");
	}

	digestA = EVP_MD_CTX_new();

	/*
	 * 1. Start digest A
	 * 2. Add the password string to digest A
	 * 3. Add the salt to digest A
	 */
	if (digestA == NULL
	    || !EVP_DigestInit_ex(digestA, sha, NULL)
	    || !EVP_DigestUpdate(digestA, passwd_binary, len)
	    || !EVP_DigestUpdate(digestA, dec_salt_binary, salt_len))
	{
		EVP_MD_CTX_free(digestA);
		elog(ERROR, "cannot create encrypted password");
	}

	/*
	 * 4. Start digest B
	 */
	digestB = EVP_MD_CTX_new();

	/*
	 * 5. Add password to digest B
	 * 6. Add the salt string to digest B
	 * 7. Add the password again to digest B
	 * 8. Finalize digest B
	 */
	if (digestB == NULL
	    || !EVP_DigestInit_ex(digestB, sha, NULL)
	    || !EVP_DigestUpdate(digestB, passwd_binary, len)
	    || !EVP_DigestUpdate(digestB, dec_salt_binary, salt_len)
	    || !EVP_DigestUpdate(digestB, passwd_binary, len)
	    || !EVP_DigestFinal_ex(digestB, sha_buf, NULL))
	{
		goto error;
	}

	/*
	 * 9. For each block of (excluding the NULL byte), add
	 *    digest B to digest A.
	 */
	for (block = len; block > buf_size; block -= buf_size)
	{

		if (!EVP_DigestUpdate(digestA, sha_buf, buf_size))
		{
			goto error;
		}

	}

	/* 10 For the remaining N bytes of the password string, add
	 * the first N bytes of digest B to A */
	if (!EVP_DigestUpdate(digestA, sha_buf, block))
	{
		goto error;
	}

	/*
	 * 11 For each bit of the binary representation of the length of the
	 * password string up to and including the highest 1-digit, starting
	 * from to lowest bit position (numeric value 1)
	 *
	 * a) for a 1-digit add digest B (sha_buf) to digest A
     * b) for a 0-digit add the password string
	 */

	block = len;
	while(block)
	{
		if (!EVP_DigestUpdate(digestA,
							  (block & 1) ? sha_buf : (const unsigned char *)passwd_binary,
							  (block & 1) ? buf_size : len))
		{
			goto error;
		}

		/* right shift to next byte */
		block >>= 1;
	}

	/* 12 Finalize digest A */
	if (!EVP_DigestFinal_ex(digestA, sha_buf, NULL))
	{
		goto error;
	}

	/* 13 Start digest DP */
	if (!EVP_DigestInit_ex(digestB, sha, NULL))
	{
		goto error;
	}

	/*
	 * 14 Add every byte of the password string (excluding trailing NULL)
	 * to the digest DP
	 */
	for (block = len; block > 0; block--) {
		if (!EVP_DigestUpdate(digestB, passwd_binary, len)) {
			goto error;
		}
	}

	/* 15 Finalize digest DP */
	if (!EVP_DigestFinal_ex(digestB, sha_buf_tmp, NULL))
	{
		goto error;
	}

	/*
	 * 16 produce byte sequence P with same length as password.
	 *
	 *     a) for each block of 32 or 64 bytes of length of the password
	 *        string the entire digest DP is used
	 *     b) for the remaining N (up to  31 or 63) bytes use the
	 *         first N bytes of digest DP
	 */
	if ((p_bytes = palloc0(len)) == NULL)
	{
		goto error;
	}

	/* N step of 16, copy over the bytes from password */
	for (cp = p_bytes, block = len; block > buf_size; block -= buf_size, cp += buf_size)
		memcpy(cp, sha_buf_tmp, buf_size);
	memcpy(cp, sha_buf_tmp, block);

	/*
	 * 17 Start digest DS
	 */
	if (!EVP_DigestInit_ex(digestB, sha, NULL))
	{
		goto error;
	}

	/*
	 * 18 Repeat the following 16+A[0] times, where A[0] represents the first
	 *    byte in digest A interpreted as an 8-bit unsigned value
	 *    add the salt to digest DS
	 */
	for (block = 16 + sha_buf[0]; block > 0; block--)
	{
		if (!EVP_DigestUpdate(digestB, dec_salt_binary, salt_len)) {
			goto error;
		}
	}

	/*
	 * 19 Finalize digest DS
	 */
	if (!EVP_DigestFinal_ex(digestB, sha_buf_tmp, NULL))
	{
		goto error;
	}

	/*
	 * 20 Produce byte sequence S of the same length as the salt string where
	 *
	 * a) for each block of 32 or 64 bytes of length of the salt string the
	 *     entire digest DS is used
	 *
	 * b) for the remaining N (up to  31 or 63) bytes use the first N
	 *    bytes of digest DS
	 */
	if ((s_bytes = palloc0(salt_len)) == NULL)
		goto error;

	for (cp = s_bytes, block = salt_len; block > buf_size; block -= buf_size, cp += buf_size) {
		memcpy(cp, sha_buf_tmp, buf_size);
	}
	memcpy(cp, sha_buf_tmp, block);

	/*
	 * 21 Repeat a loop according to the number specified in the rounds=<N>
	 *    specification in the salt (or the default value if none is
	 *    present).  Each round is numbered, starting with 0 and up to N-1.
	 *
	 *    The loop uses a digest as input.  In the first round it is the
	 *    digest produced in step 12.  In the latter steps it is the digest
	 *    produced in step 21.h of the previous round.  The following text
	 *    uses the notation "digest A/C" to describe this behavior.
	 */
	for (block = 0; block < rounds; block++) {

		if (!EVP_DigestInit_ex(digestB, sha, NULL))
			goto error;

		if (!EVP_DigestUpdate(digestB,
		                      (block & 1) ? (const unsigned char *)p_bytes : sha_buf,
		                      (block & 1) ? len : buf_size))
			goto error;

		if (block % 3) {
			if (!EVP_DigestUpdate(digestB, s_bytes, salt_len))
				goto error;

		}

		if (block % 7) {
			if (!EVP_DigestUpdate(digestB, p_bytes, len))
				goto error;
		}

		if (!EVP_DigestUpdate(digestB,
		                      (block & 1) ? sha_buf : (const unsigned char *)p_bytes,
		                      (block & 1) ? buf_size : len))
			goto error;

		if (!EVP_DigestFinal_ex(digestB, sha_buf, NULL))
			goto error;

	}

	/* Free resources */
	EVP_MD_CTX_free(digestB);
	EVP_MD_CTX_free(digestA);

	digestA = NULL;
	digestB = NULL;

	pfree(s_bytes);
	pfree(p_bytes);

	s_bytes = NULL;
	p_bytes = NULL;

	/* prepare final result buffer */
	cp = out_buf + strlen(out_buf);
	*cp++ = ascii_dollar[0];

# define b64_from_24bit(B2, B1, B0, N)                                  \
    do {                                                                \
        unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);             \
        int i = (N);                                                    \
        while (i-- > 0)                                                 \
            {                                                           \
                *cp++ = cov_2char[w & 0x3f];                            \
                w >>= 6;                                                \
            }                                                           \
    } while (0)

	switch(type)
	{
		case PGCRYPTO_SHA256CRYPT:
		{
			b64_from_24bit (sha_buf[0], sha_buf[10], sha_buf[20], 4);
			b64_from_24bit (sha_buf[21], sha_buf[1], sha_buf[11], 4);
			b64_from_24bit (sha_buf[12], sha_buf[22], sha_buf[2], 4);
			b64_from_24bit (sha_buf[3], sha_buf[13], sha_buf[23], 4);
			b64_from_24bit (sha_buf[24], sha_buf[4], sha_buf[14], 4);
			b64_from_24bit (sha_buf[15], sha_buf[25], sha_buf[5], 4);
			b64_from_24bit (sha_buf[6], sha_buf[16], sha_buf[26], 4);
			b64_from_24bit (sha_buf[27], sha_buf[7], sha_buf[17], 4);
			b64_from_24bit (sha_buf[18], sha_buf[28], sha_buf[8], 4);
			b64_from_24bit (sha_buf[9], sha_buf[19], sha_buf[29], 4);
			b64_from_24bit (0, sha_buf[31], sha_buf[30], 3);

			break;
		}

		case PGCRYPTO_SHA512CRYPT:
		{
			b64_from_24bit (sha_buf[0], sha_buf[21], sha_buf[42], 4);
			b64_from_24bit (sha_buf[22], sha_buf[43], sha_buf[1], 4);
			b64_from_24bit (sha_buf[44], sha_buf[2], sha_buf[23], 4);
			b64_from_24bit (sha_buf[3], sha_buf[24], sha_buf[45], 4);
			b64_from_24bit (sha_buf[25], sha_buf[46], sha_buf[4], 4);
			b64_from_24bit (sha_buf[47], sha_buf[5], sha_buf[26], 4);
			b64_from_24bit (sha_buf[6], sha_buf[27], sha_buf[48], 4);
			b64_from_24bit (sha_buf[28], sha_buf[49], sha_buf[7], 4);
			b64_from_24bit (sha_buf[50], sha_buf[8], sha_buf[29], 4);
			b64_from_24bit (sha_buf[9], sha_buf[30], sha_buf[51], 4);
			b64_from_24bit (sha_buf[31], sha_buf[52], sha_buf[10], 4);
			b64_from_24bit (sha_buf[53], sha_buf[11], sha_buf[32], 4);
			b64_from_24bit (sha_buf[12], sha_buf[33], sha_buf[54], 4);
			b64_from_24bit (sha_buf[34], sha_buf[55], sha_buf[13], 4);
			b64_from_24bit (sha_buf[56], sha_buf[14], sha_buf[35], 4);
			b64_from_24bit (sha_buf[15], sha_buf[36], sha_buf[57], 4);
			b64_from_24bit (sha_buf[37], sha_buf[58], sha_buf[16], 4);
			b64_from_24bit (sha_buf[59], sha_buf[17], sha_buf[38], 4);
			b64_from_24bit (sha_buf[18], sha_buf[39], sha_buf[60], 4);
			b64_from_24bit (sha_buf[40], sha_buf[61], sha_buf[19], 4);
			b64_from_24bit (sha_buf[62], sha_buf[20], sha_buf[41], 4);
			b64_from_24bit (0, 0, sha_buf[63], 2);

			break;
		}
		
		default:
			goto error;
	}

	*cp = '\0';

	ret = cstring_to_text(out_buf);

	PG_RETURN_TEXT_P(ret);

error:

	EVP_MD_CTX_free(digestA);
	EVP_MD_CTX_free(digestB);
	elog(ERROR, "cannot create encrypted password");
	
}