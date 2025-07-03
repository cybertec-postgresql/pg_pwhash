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

Normally this builds `pgxcrypto_pwhash` without OpenSSL support for Argon2 password hashing, but
it can be turned on by the `_PGXCRYPTO_ARGON2_OSSL_SUPPORT` compiler macro:

```shell
make -D _PGXCRYPTO_ARGON2_OSSL_SUPPORT=1 && make install
```

Please note that this doesn't test for `libscrypt` and `libargon2` presence and API compatibility automatically.

Thus, best option is to use `meson`:

```shell
mkdir build && meson setup build .
cd build
ninja

# you might need a privileged user to do this, depending on
# environment
ninja install
```

Building with `meson` is recommended, since this allows for some detailed preliminary checks before 
compiling. It checks for API compatibility and automatically chooses the right compiler flags if
compatible libraries are found (e.g. OpenSSL).

If all prerequisites are as expected, this will compile the extension and generate the 
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

The following table shows the algorithms and backends implemented to generate hashes:

| Hash     | Backend     | Function             |
|----------|-------------|----------------------|
 | Argon2i  | libargon2   | `pgxcrypto_argon2()` |
 |          | OpenSSL 3.2 | *                    |
 | Argon2d  | libargon2   | *                    |
  |          | OpenSSL 3.2| * |    
 | Argon2id | libargon2   | * |
 |          | OpenSSL 3.2 | * |
 | scrypt   | libscrypt | `pgxcrypto_scrypt()` |
 |          | OpenSSL 3.0 | * |
 |          | crypt (libxcrypt) | `pgxcrypto_scrypt_crypt()` |
 | yescrypt | crypt (libxcrypt) | `pgxcrypto_yescrypt_crypt()` |

The `Argon2` default backend can be controlled by the GUC `pgxcrypto.argon2_default_backend`. This is
currently not implemented for `scrypt`. `yescrypt` currently only supports the `crypt()` API
provided by the underyling operating system (or `libxcrypt`, `libc` specifically). See the table below
which function can be used. See below for a more detailed description of the supported algorithms.

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
────────────────────────────────────────────────────────────────
 $scrypt$ln=4,r=4,p=8,backend=libscrypt$T4uc3FoIkOLQf+IFtJr/zQ$
(1 Zeile)

```

Or with long option names specified:

```postgresql
SELECT pgxcrypto_gen_salt('scrypt', 'rounds=4', 'block_size=4', 'parallelism=8');
pgxcrypto_gen_salt                       
────────────────────────────────────────────────────────────────
 $scrypt$ln=4,r=4,p=8,backend=libscrypt$JiyCfakZWYdJJh8i+g5XFA$
```

## Argon2

`pgxcrypto` supports password hashing via Argon2 which is hashing algorithms `argon2i`, 
`argon2d` and `argon2id`.

Argon2 password hashing is implemented via [OpenSSL](https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/) 
and [libargon2](https://github.com/P-H-C/phc-winner-argon2), specified via [RFC9106](https://www.rfc-editor.org/rfc/rfc9106.html#name-argon2-algorithm). 
To compile `pgxcrypto` with OpenSSL support, you need at least OpenSSL 3.2. 
Currently this is only shipped on relatively recent distributions.

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
- `backend`: Choose between `openssl` and `libargon2` backend to create the password 
  digest. Note: `openssl` requires at least OpenSSL >= 3.2 to work. `libargon2` is the default. 

The long format of parameters names are exclusive to `pgxcrypto_pwhash` and not supported for use 
outside of the scope of this extension. Instead, use the short format. This is also the reason why
generated hashes always use the short format.

Argon2 hashes can be generated by the `pgxcrypto_argon2()` function, like the following example
illustrates:

1. `pgxcrypto_argon2()`: Use either `OpenSSL` or `libargon2` backend to generate password hashes
```postgresql
SELECT pgxcrypto_argon2('password', pgxcrypto_gen_salt('argon2id'));
                                         pgxcrypto_argon2                                         
──────────────────────────────────────────────────────────────────────────────────────────────────
 $argon2id$v=19$m=4096,t=3,p=1$/iB/+R2eoJ9JYRcuwnDTRw$CnDxaPnux1vmsSPKTUtTOhahmE1MxG0dU15EqR5Klz8
```

## Argon2 backends

`Argon2` can use either implementations based on `libargon2` or `OpenSSL`. `pgxcrypto_pwhash` supports
the GUC `pgxcrypto.argon2_default_backend` to control the default backend. This is currently set to
`libargon2` per default. Additionally it is possible to control the backend for hashing by the parameter `backend` when
using the `pgxcrypto_gen_salt()` function. The following example shows the behavior. Please note
that this uses `DEBUG`, to show the effect of the parameter:

```postgresql
SET client_min_messages TO DEBUG;

SELECT pgxcrypto_argon2('password', pgxcrypto_gen_salt('argon2d', 'backend=libargon2'));
DEBUG:  extracted options from salt "m=4096,t=3,p=1,backend=libargon2"
DEBUG:  extracted m=4096, len 6
DEBUG:  extracted t=3, len 3
DEBUG:  extracted p=1, len 3
DEBUG:  extracted backend=libargon2, len 17
DEBUG:  using salt "jdDylbvpR5YGKvi3LRoljA"
DEBUG:  hashing password with Argon2 method "ARGON2D"
DEBUG:  using libargon2 backend for argon2 hashing
                                                 pgxcrypto_argon2                                                  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 $argon2d$v=19$m=4096,t=3,p=1,backend=libargon2$jdDylbvpR5YGKvi3LRoljA$uJNICNmbAWdgTQLMQo454bs+np3x2jh0HTmxHOuX4So

SELECT pgxcrypto_argon2('password', pgxcrypto_gen_salt('argon2d', 'backend=openssl'));
DEBUG:  extracted options from salt "m=4096,t=3,p=1,backend=openssl"
DEBUG:  extracted m=4096, len 6
DEBUG:  extracted t=3, len 3
DEBUG:  extracted p=1, len 3
DEBUG:  extracted backend=openssl, len 15
DEBUG:  using salt "TykUH1E1H1a4e1V0SJYfmA"
DEBUG:  hashing password with Argon2 method "ARGON2D"
DEBUG:  using openssl backend for argon2 hashing
                                                pgxcrypto_argon2                                                 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 $argon2d$v=19$m=4096,t=3,p=1,backend=openssl$TykUH1E1H1a4e1V0SJYfmA$W9z9UzXZNsgr5Bb+HFmiLB1HmXkOf0aNFcYX/kQxqIs
(1 Zeile)
```

Please note that using the `backend` parameter is not compatible when the hash is exchanged to other systems. 
If you want to choose one backend over the other, use the GUC instead.

## scrypt

`pgxcrypto` implements the `scrypt` password hashing methods based on either `OpenSSL` or 
`libscrypt`. Currently `libscrypt` is the default.

# Usage

## Generate a salt for scrypt hashing

```postgresql
 SELECT pgxcrypto_gen_salt('scrypt');
        pgxcrypto_gen_salt         
───────────────────────────────────
 $scrypt$$cz3jl57IKTE5H08+9vN9aA==
```

The function `pgxcrypto_scrypt()` can be used to generate a password hash based on `scrypt`. The following
example shows how to achieve this in connection with a generated salt:

```postgresql
SELECT pgxcrypto_scrypt('password', pgxcrypto_gen_salt('scrypt'));
                                      pgxcrypto_scrypt                                     
──────────────────────────────────────────────────────────────────────────────────────────
 $scrypt$ln=16,r=8,p=1$c7CBZ3Tzmiydxo+YlF8aPg$OlDtyFDGXB9lTeUWLou4iHqMZ/oLyI/NySJRL3E5QIo
```

## Available options

When generating hashes based on `scrypt`, the following parameters can be used to configure and influence
the strength and security of the resulting hash:

- `block_size/r`: This specifies the `block size` used for hashing. The default is `8`. The allowed
range currently is from `1` to `1024`, but the upper limit might change once we know where a practical value exactly exists.
Adjusting this value might be interesting to get optimal performance on your specific CPU.
- `rounds/ln`: This adjusts the cost parameter used when calculating the hashes. Raising this value
not only increases CPU time but also memory consumption. So it should be used with careful testing.
_NOTE_: The default used here is `16`, allowed range is from `1` to `32`. Though testing shows that `OpenSSL`
allows values up to `21` only, going above this limit yields the following error where `libscrypt` succeeds:

```postgresql
SELECT pgxcrypto_scrypt('password', pgxcrypto_gen_salt('scrypt', 'backend=openssl', 'rounds=22'));
FEHLER:  cannot derive test vector

SELECT pgxcrypto_scrypt('password', pgxcrypto_gen_salt('scrypt', 'backend=libscrypt', 'rounds=22'));
                                     pgxcrypto_scrypt                                     
──────────────────────────────────────────────────────────────────────────────────────────
 $scrypt$ln=22,r=8,p=1$neYEJsDLFnGdd0eNLb4w4w$dFfmTCL7gvJpDcShAWRxq/7i1pZmxtAKP1o8mx3wK9o
```

- `parallelism/p`: The number of parallel calculations. Default is `1`. The allowed values are `1` to
`1024`.
- `backend`: This is an extension to the list of supported parameters propietary to `pgxcrypto_pwhash()`. This allows to
switch from the default backend `libscrypt` to `openssl`.

The generated hashes should be compatible with python's `passlib` and OpenSSL.

Note:

When using the `backend` parameter it is currently not reflected in the final salt string. This is in contrast to
`Argon2` above and we might change this in the near future. There is currently also no GUC to control
the backend to use.

Example:

```postgresql
SELECT pgxcrypto_scrypt('password', pgxcrypto_gen_salt('scrypt', 'backend=openssl', 'rounds=10'));
                                     pgxcrypto_scrypt                                     
──────────────────────────────────────────────────────────────────────────────────────────
 $scrypt$ln=10,r=8,p=1$wjrlkqMnLxApYWlg/RJ4bw$2GeCUzd619THLC6gC5V6ROnVFiQp5kjPWiVDKJM1TDQ
```

## Wrapper to `crypt()`

There is also an implementation on top of `crypt`, though this generates hashes which are incompatible with the other
implementations based on `libscrypt` or `OpenSSL`. Both use the magic string `$scrypt$`, whereas `crypt()`
used `$7$` to identify such hashes. Also the list of parameters differ, so that the implementation here
to leverage `crypt()` differs significantly from the others. Thus, `pgxcrpyto_pwhash` uses a different
function to generate `scrypt` hashes via `crypt()`:

```postgresql
SELECT pgxcrypto_scrypt_crypt('password', pgxcrypto_gen_salt('$7$', 'rounds=10'));
                              pgxcrypto_scrypt_crypt                              
──────────────────────────────────────────────────────────────────────────────────
 $7$FU..../....RBoa8sCnl7KAMVQdtzulZ.$2Q.uFm5t0Q0QBprwQRsNKmNhY7jXwRyBLLs4VuAqRn4
```

Please note that you can just use `pgxcrypto_gen_salt()` to generate a salt suitable for
`pgxcrypto_scrypt_crypt()`, just use the correct magic string as the hash identifier. Using `scrypt` yields an error:

```postgresql
SELECT pgxcrypto_scrypt_crypt('password', pgxcrypto_gen_salt('scrypt', 'rounds=10'));
ERROR:  invalid magic string for crypt()
```

# yescrypt

`yescrypt` is currently implemented on top of `crypt()`. There is a standalone implementation available, but
not as a shared library or API or such. We might adapt the implementation by Openwall, but its unclear what
licensing they provide:

https://www.openwall.com/yescrypt/

## Usage

Password hashes can be created via `pgxcrpyto_yescrypt_crypt()`:

```postgresql
SELECT pgxcrypto_yescrypt_crypt('password', pgxcrypto_gen_salt('yescrypt', 'rounds=10'));
                         pgxcrypto_yescrypt_crypt                          
───────────────────────────────────────────────────────────────────────────
$y$jET$CW.pzV.XWCv8PNDci9KBK1$.2stwXKqgRYVMEfJ6H4yFwAp4uKjPxuovwes2e9hTgD
```

## Available options

- `rounds`: This parameter is passed to `crypt()` and specifies the computing time spent to generate the hash. 
Allowed values are from `1` to `11` (limited by `crypt()`). The default is `5`. Raise this value if
you want to create hardened password hashes.

# The `pgxcrypto_crypt()` function

The `pgxcrypt_crypt()` function acts as a wrapper on top of all the algorithms above and serves as a
unique call site for generating hashes. Its usage is compatible to `crypt()` and supports all of
the described algorithms above.

Example:



# Caveats

1. We currently are a little schizo regarding the `backend` options used by `Argon2` and `scrypt` hashes.
`Argon2` emits them in the final password hash string, where `scrypt` doesn't. This confusing behavior
needs to be changed, though it's not really clear what to follow (see next point below).
2. Only `Argon2` currently supports a GUC to configure the backend to use for hashing. We should
probably adapt this for `scrypt`, too.



