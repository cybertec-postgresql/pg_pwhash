BEGIN;

\timing on

CREATE TEMP TABLE tt_random_pw(pw text not null);
\copy tt_random_pw from 'random_passwords.txt';

\echo Hashing with OpenSSL
DO LANGUAGE plpgsql
$$
DECLARE
        v_rand_pw text;
BEGIN

        FOR v_rand_pw IN SELECT pw FROM tt_random_pw LIMIT 1000
        LOOP

                PERFORM pwhash_crypt(v_rand_pw, pwhash_gen_salt('scrypt', 'backend=openssl'));

        END LOOP;

END;
$$;

\echo Hashing with libscrypt
DO LANGUAGE plpgsql
$$
DECLARE
        v_rand_pw text;
BEGIN

        FOR v_rand_pw IN SELECT pw FROM tt_random_pw LIMIT 1000
        LOOP

                PERFORM pwhash_crypt(v_rand_pw, pwhash_gen_salt('scrypt', 'backend=libscrypt'));

        END LOOP;

END;
$$;


COMMIT;
