project('pgxcrypto_poc', ['c'])

pg_config = find_program('pg_config')

bindir = run_command(pg_config, '--bindir', check: true).stdout().strip()
includedir_server = run_command(pg_config, '--includedir-server', check: true).stdout().strip()
pkglibdir = run_command(pg_config, '--pkglibdir', check: true).stdout().strip()
sharedir = run_command(pg_config, '--sharedir', check: true).stdout().strip()

# check for libscrypt
cc = meson.get_compiler('c')
pgxcrypto_dep = cc.find_library('scrypt')

shared_module('pgxcrypto_poc', 'pgxcrypto_poc.c',
              'pgxcrypto_scrypt.c', 'pgxcrypto_yescrypt.c', 'pgxcrypto_argon2.c',
              include_directories: [includedir_server],
              install: true,
              install_dir: pkglibdir,
              name_prefix: '',
              dependencies: pgxcrypto_dep
             )

install_data('pgxcrypto_poc.control',
             'pgxcrypto_poc--1.0.sql',
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

regress_tests = []

test('regress',
     pg_regress,
     args: ['--bindir', bindir,
            '--inputdir', meson.current_source_dir() / 'test',
           ] + regress_tests,
    )

