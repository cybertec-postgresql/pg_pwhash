project('pgxcrypto_pwhash', ['c'])

pg_config = find_program('pg_config')

bindir = run_command(pg_config, '--bindir', check: true).stdout().strip()
includedir_server = run_command(pg_config, '--includedir-server', check: true).stdout().strip()
pkglibdir = run_command(pg_config, '--pkglibdir', check: true).stdout().strip()
sharedir = run_command(pg_config, '--sharedir', check: true).stdout().strip()

# check for libscrypt
cc = meson.get_compiler('c')
pgxcrypto_scrypt_dep = cc.find_library('scrypt')

# check for libargon2
pgxcrypto_argon2_dep = cc.find_library('argon2')

# need libm (libmath)
pgxcrypto_libm_dep = cc.find_library('m')

# need libcrypt
pgxcrypto_crypt_dep = cc.find_library('crypt')

shared_module('pgxcrypto_pwhash',
              'pgxcrypto_scrypt.c', 'pgxcrypto_yescrypt.c', 'pgxcrypto_argon2.c',  'pgxcrypto_pwhash.c',
              include_directories: [includedir_server],
              install: true,
              install_dir: pkglibdir,
              name_prefix: '',
              dependencies: [ pgxcrypto_libm_dep, pgxcrypto_scrypt_dep,
                              pgxcrypto_argon2_dep, pgxcrypto_crypt_dep ]
             )

install_data('pgxcrypto_pwhash.control',
             'pgxcrypto_pwhash--1.0.sql',
             install_dir: sharedir / 'extension',
            )

# check if libscrypt_hash is available
code = '''#include <libscrypt.h>
int main(int argc, char **argv)
{
    char *outbuf;
    int rc = libscrypt_hash(outbuf, "hello world", SCRYPT_N, SCRYPT_r, SCRYPT_p);
    return 0;
}
'''

result = cc.links(code, args: '-lscrypt', name: 'libscrypt_hash() works')

# check OpenSSL 3.2.0 dependency
ossldep = dependency('openssl', version : '>=3.2.0')

pg_regress = find_program('pg_regress',
                          dirs: [pkglibdir / 'pgxs/src/test/regress']
                         )
# check for argon2 API
code = '''
#include <stdlib.h>
#include <string.h>
#include <argon2.h>

int main(int argc, char **argv)
{
    size_t size = 32;
    char *hash = malloc(size);
    char *pw   = "password";
    char *salt = "abcdef";
    argon2_context context;
    int rc;

	context.out    = hash;  /* output array, at least HASHLEN in size */
	context.outlen = size; /* digest length */
	context.pwd    = (uint8_t *)pw; /* password array */
	context.pwdlen = strlen(pw); /* password length */
	context.salt   = salt;  /* salt array */
	context.saltlen = strlen((char *)salt); /* salt length */
	context.secret  = NULL;
	context.secretlen = 0;  /* optional secret data */
	context.ad        =	NULL;
	context.adlen     = 0; /* optional associated data */
	context.t_cost    =	3;
	context.m_cost    = 4096;
	context.lanes     = 1;
	context.threads   = 1;
	context.version   = 0x13; /* algorithm version */
	context.allocate_cbk = NULL;
	context.free_cbk     = NULL; /* custom memory allocation / deallocation functions */
	/* by default only internal memory is cleared (pwd is not wiped) */
	context.flags        = ARGON2_DEFAULT_FLAGS;

	rc = argon2id_ctx(&context);
	rc = argon2d_ctx(&context);
	rc = argon2i_ctx(&context);
}
'''

result = cc.links(code, args: '-largon2', name: 'argon2*_ctx() API works')

regress_tests = [ 'pgxcrypto' ]

test('regress',
     pg_regress,
     args: ['--bindir', bindir,
            '--inputdir', meson.current_source_dir(),
           ] + regress_tests,
    )
