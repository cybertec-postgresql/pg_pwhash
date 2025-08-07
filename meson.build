project('pg_pwhash', ['c'], version: '1.0')

pg_config = find_program('pg_config')
build_args = []

pg_config_version_str = run_command(pg_config, '--version', check: true).stdout().strip()
message('pg_config version: ' + pg_config_version_str)

bindir = run_command(pg_config, '--bindir', check: true).stdout().strip()
includedir_server = run_command(pg_config, '--includedir-server', check: true).stdout().strip()
pkglibdir = run_command(pg_config, '--pkglibdir', check: true).stdout().strip()
sharedir = run_command(pg_config, '--sharedir', check: true).stdout().strip()

# check for libscrypt
cc = meson.get_compiler('c')
pgxcrypto_scrypt_dep = cc.find_library('scrypt', required: false)

# check for libargon2
pgxcrypto_argon2_dep = cc.find_library('argon2', required: true)

# need libm (libmath)
pgxcrypto_libm_dep = cc.find_library('m', required: true)

# need libcrypt
pgxcrypto_crypt_dep = cc.find_library('crypt', required: true)

install_data('pg_pwhash.control',
             'pg_pwhash--1.0.sql',
             install_dir: sharedir / 'extension',
            )

if pgxcrypto_scrypt_dep.found()

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

   if not result
      error('libscrypt_hash() API not supported by libscrypt')
   endif

   # we're safe no, enable libscrypt support
   build_args += '-D_PWHASH_LIBSCRYPT_SUPPORT=1'
   message('setting build flag -D"_PWHASH_LIBSCRYPT_SUPPORT=1"')

else

   message('disabling libscrypt support since libscrypt is missing')

endif

# #################################################################################################
# check OpenSSL 3.2.0 dependency

#ossldep = dependency('openssl', version : '>=3.2.0')

# Check if openssl/thread.h is present
if cc.check_header('openssl/thread.h')

    code = '''
#include "openssl/core_names.h"
#include <stdlib.h>

int main(int argc, char **argv)
{
    /* Checks if OSSL_KDF_PARAM_ARGON2_VERSION is defined */
#ifdef OSSL_KDF_PARAM_ARGON2_VERSION
    exit(0);
#else
#error OSSL_KDF_PARAM_ARGON2_VERSION not defined.
#endif
}
'''

    if cc.links(code, args: '-lssl', name: 'check if OpenSSL provides Argon2 KDF support')
        build_args += '-D_PWHASH_ARGON2_OSSL_SUPPORT=1'
        message('setting build flag -D"_PWHASH_ARGON2_OSSL_SUPPORT=1"')
    endif

else
    # this means this is an OpenSSL version likely older than 3.2.0
    message('OpenSSL support for Argon2 not available')
endif

# #################################################################################################

pg_regress = find_program('pg_regress',
                          dirs: [pkglibdir / 'pgxs/src/test/regress']
                         )
# #################################################################################################
# Check if Argon2 API we use is supported

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

result = cc.links(code, args: '-largon2', name: 'argon2*_ctx() API')

if not result
    error('argon2_ctx() API not supported by existing libargon2')
endif

# #################################################################################################

# #################################################################################################
# Check if crypt() supports scrypt

code = '''
#include <stdlib.h>
#include <crypt.h>
#include <errno.h>
int main(int argc, char **argv)
{
    char *salt = crypt_gensalt("$7$", 6, NULL, 0);

    if (errno == EINVAL)
        exit(1);
    else
        exit(0);
}
'''

result = cc.run(code, args: '-lcrypt', name: 'crypt() scrypt support')

if result.returncode() == 0
    build_args += '-D_PWHASH_CRYPT_SCRYPT_SUPPORT=1'
    message('setting build flag _PWHASH_CRYPT_SCRYPT_SUPPORT=1')
else
    message('crypt() support for scrypt not available')
endif

# #################################################################################################

# #################################################################################################
# Check if crypt() supports yescrypt

code = '''
#include <stdlib.h>
#include <crypt.h>
#include <errno.h>
int main(int argc, char **argv)
{
    char *salt = crypt_gensalt("$y$", 6, NULL, 0);

    if (errno == EINVAL)
        exit(1);
    else
        exit(0);
}
'''

result = cc.run(code, args: '-lcrypt', name: 'crypt() yescrypt support')

if result.returncode() == 0
    build_args += '-D_PWHASH_CRYPT_YESCRYPT_SUPPORT=1'
    message('setting build flag _PWHASH_CRYPT_YESCRYPT_SUPPORT=1')
else
    message('crypt() support for yescrypt not available')
endif

# #################################################################################################

regress_tests = [ 'pg_pwhash' ]

test('regress',
     pg_regress,
     args: ['--bindir', bindir,
            '--inputdir', meson.current_source_dir(),
           ] + regress_tests,
    )

shared_module('pg_pwhash',
              'pwhash_scrypt.c', 'pwhash_yescrypt.c', 'pwhash_argon2.c',  'pg_pwhash.c',
              c_args: build_args,
              include_directories: [includedir_server],
              install: true,
              install_dir: pkglibdir,
              name_prefix: '',
              dependencies: [ pgxcrypto_libm_dep, pgxcrypto_scrypt_dep,
                              pgxcrypto_argon2_dep, pgxcrypto_crypt_dep ]
             )