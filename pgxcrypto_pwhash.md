# Motivation

This extension adds advanced password hashing algorithms to PostgreSQL databases.

# Requirements

To build `pgxcrypto_pwhash` you need OpenSSL version >= `3.2` and `libscrypt` installed. Argon2 support
is additionally provided by the `libargon2` library backend, too.

If you use meson to built the extension, then check the output, since `meson setup` will check 
whether prerequisites are met.

# Installation


```shell
make && make install
```

or via meson

```shell
mkdir build && meson setup build .
cd build
ninja

# you might need a privileged user to do this, depending on
# environment
ninja install
```

If all prerequisites are as expected this will compile the extension and generate the 
`pgxcrypto.so` shared library. Then load the new extension into your PostgreSQL instance:

```shell
psql <YOUR_DB>
CREATE EXTENSION pgxcrypto_pwhash;
```

# Features

This extension currently implements advanced password hashing via `argon2id`,  `argon2i`, `argon2d` 
and `scrypt` hashing algorithms. Additionally  `pgxcrypto_pwhash` supports `yescrypt` by `libxcrypt`
implementations, if available on the target platform. In the future a standalone implementation based on
[https://github.com/openwall/yescrypt](https://github.com/openwall/yescrypt) will be added.

## Generating salts

`pgxcrypto` features the `pgxcrypto_gen_salt()` function with accepts the requested name of the
password hash algorithm and a variadic list of options which should be passed to the specified
algorithm. These options are specific to the requested algorithm, see the next chapter below.

```postgresql
CREATE OR REPLACE FUNCTION pgxcrypto_gen_salt(text, VARIADIC text[])
    RETURNS text
AS 'MODULE_PATHNAME', 'xgen_salt'
    LANGUAGE C VOLATILE STRICT PARALLEL RESTRICTED ;
```

For example, if you want to generate a salt string suitable for password hashing via `argon2id`,
you can use `pgxcrypto_gen_salt()` like the following example:

```postgresql
SELECT pgxcrypto_gen_salt('argon2id');
                   pgxcrypto_gen_salt                   
────────────────────────────────────────────────────────
 $argon2id$v=19$m=4096,t=3,p=1$vfFgk5evN+y7xSC1YYs1Ew==
(1 row)
```
This generates a salt string suitable to used to generate a password digest with the `argon2id` 
algorithm. The salt bytes are 16 bytes total and guaranteed to be completely randomized. Output
is always `base64` encoded (PEM format via OpenSSL). 

To support a generic way of passing options, you have the specify them as `key=value` pairs. 
This is done by passing them as additional options to `pgxcrypto_gen_salt`, which are declared 
`VARIADIC`. The following is an example with `scrypt`:

```postgresql
SELECT pgxcrypto_gen_salt('scrypt', 'ln=4', 'r=4', 'p=8');
                                            pgxcrypto_gen_salt                                            
──────────────────────────────────────────────────────────────────────────────────────────────────────────
 $7$ln=4,r=4,p=8$cuZfNhiDN0kIjThWJkHo0m4r1GkxZBRANItkL9/OhEC81ulFyEGs6UjuXKFJBS02G+07s7YfzX+eGxMGXwWpxQ==
(1 row)
```

## Argon2

`pgxcrypto` supports password hashing via Argon2 which is hashing algorithms `argon2i`, 
`argon2d` and `argon2id`.

Argon2 password hashing is implemented via [OpenSSL](https://docs.openssl.org/3.
2/man7/EVP_KDF-ARGON2/) and [RFC9106](https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-algorithm). To compile 
`pgxcrypto`, you need at least OpenSSL 3.2. Currently this is only shipped on selected 
distributions.

### Available options

`pgxcrypto_gen_salt()`

`argon2id` is adaptive and thus support a wide range of options to influence the hashing algorithm.
`pgxcrypto` currently supports the following options for `argon2id`. Please note that you should 
use the short version of the option name to be sure to be compatible with other hash sources. 
There are also some incompatible extensions, as noted in the text below.

- `threads`, `p`: This configures the number of threads OpenSSL uses to hash the input. The default 
  is `1`.
- `lanes`, `l`: This configures the memory blocks which are processed in parallel. `lanes` can be 
  larger or  equal to the number of configured `threads`, but not less. The default is using `1` lanes. Be 
  aware that changing this parameters influences the generated digest of the password. 
- `memcost`, `m`: This is the number of memory the hashing algorithm is allowed to use. This 
parameter value reflects the number of `1kB` memory blocks. The default is `4096`, which equals to 
  4096 kB of memory. Be aware that changing this parameters influences the generated digest of 
  the password.
- `rounds`, `t`: This parameter configures the number of computation rounds used to generate the 
  digest. The default is `3`. Be aware that changing this parameters influences the generated digest of the password.
- `size`: This is the tag length of the digest to generate. The default of `32` results in 256 
  Bit for the digest length (32 Bytes, not base64 encoded).
- `output_format`: This parameter is supported by `pgxcrypto` only and allows to switch between 
  `base64` encoded keys (the default) or `hex` encoded hash keys. Don't use this if you intend to 
  share the keys between systems. This affects the output of the password hash only. Mostly there 
  for testing purposes and might be removed some time.
- `backend`: Choose between `openssl` (default) and `libargon2` backend to create the password 
  digest. Note: `openssl` requires at least OpenSSL >= 3.2 to work. 

The extension to the list of parameters made by this extensionsare experimental at the  moment 
and will change. This will cause compatibility issues, so be aware when storing hash strings 
with these kind of parameters!

## scrypt

`pgxcrypto` implements the `scrypt` password hashing methods based on either OpenSSL or 
`libscrypt`.

# Usage

## Generate a salt for scrypt hashing

```postgresql
 SELECT pgxcrypto_gen_salt('scrypt');
        pgxcrypto_gen_salt         
───────────────────────────────────
 $scrypt$$cz3jl57IKTE5H08+9vN9aA==
(1 Zeile)
```

TBD

# Compatibility

TBD
