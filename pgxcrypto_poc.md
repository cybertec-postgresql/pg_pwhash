# Motivation

This POC aims to showcase the implementation of `scrypt` and `argon2id` in
PostgreSQL to provide an advanced password hashing algorithm.

# Requirements

To build `pgxcrypto_poc` you need OpenSSL version >= `3.2` and `libscrypt` installed.
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
CREATE EXTENSION pgxcrypto_poc;
```

At the moment `pgxcrypto_poc` requires `pgcrypto` to be installed, but this requirement will be
be relaxed in the final version.

# Features

This extension currently implements advanced password hashing via `argon2id` and `scrypt` hashing 
algorithms.

## Generating salts

`pgxcrypto` features the `pgxcrpyto_gen_salt()` function with accepts the requested name of the
password hash algorithm and an variadic list of options which should be passed to the specified
algorithm. These options are specific to the requested algorithm, see the next chapter below.

```postgresql
CREATE OR REPLACE FUNCTION pgxcrypto_gen_salt(text, VARIADIC text[])
    RETURNS text
AS 'MODULE_PATHNAME', 'xgen_salt'
    LANGUAGE C VOLATILE STRICT PARALLEL RESTRICTED ;
```

For example, if you want to generate a salt string suitable for password hashing via `argon2id`,
you use `pgxcrypto_gen_salt()` like the following example:

```postgresql
bernd@localhost:bernd :1 #= SELECT pgxcrypto_gen_salt('argon2id', 'threads=2', 'memcost=4096', 'rounds=3');
            pgxcrypto_gen_salt             
───────────────────────────────────────────
 $argon2id$m=4096,t=3,p=2$DcX3AacYoA3wSfi2
(1 row)
```

## Argon2i

`argon2id` password hashing is implemented via [OpenSSL](https://docs.openssl.org/3.
2/man7/EVP_KDF-ARGON2/) and [RFC9106](https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-algorithm). To compile 
`pgxcrypto`, you need at least OpenSSL 3.2. Currently this is only shipped on selected 
distributions, so you need to enable support for `argon2id` password hashing explicitely.

### Available options

`pgxcrypto_gen_salt()`

`argon2id` is adaptive and thus support a wide range of options to influence the hashing algorithm.
`pgxcrypto` currently supports the following options for `argon2id`:

- `threads`: This configures the number of threads OpenSSL uses to hash the input. The default 
  is `1`.
- `lanes`: This configures the blocks which are processed in parallel. `lanes` can be larger or 
  equal to the number of configured `threads`, but not less. The default is using `2` lanes.
- `memcost`: This is the number of memory the hashing algorithm is allowed to use. The parameter 
  value reflects the number of `1kB` memory blocks. The default is `64`, which equals to 64 kB 
  of memory.
- `rounds`: This parameter configures the number of computation rounds used to generate the 
  digest. The default is `3`.
- `size`: This is the tag length of the digest to generate. The default of `16` results in 128 
  Bit for the digest length (16 Bytes).
- `output_format`: This parameter is supported by `pgxcrypto` only and allows to switch between 
  `base64` encoded keys (the default) or `hex` encoded keys. Don't use this if you intend to 
  share the keys between systems.

The parameter names are experimental at the moment and will change. This will cause compatibility 
issues, so be aware when storing hash strings!

## Scrypt

`pgxcrpyto` implements the `scrypt` password hashing methods based on either OpenSSL or 
`libscrypt`.

# Usage

## Generate a salt for scrypt hashing

```postgresql
SELECT pgxcrypto_gen_salt('scrypt', 'rounds=8');
pgxcrypto_gen_salt                              
─────────────────────────────────────────────────────────────────────────────
$7$ln=1000$BJEA08TCylEe9HvVKi//8ZKXPHKKcL97ycYpwvTLa4/ah4JjbI5vDKXoCCaz.BnL
(1 row)
```

## Encrypt a password with scrypt and a generated salt
