BEGIN;

\timing on

SET pg_pwhash.argon2_default_backend TO :'_hash_backend';

CREATE TEMP TABLE tt_random_pw(pw text not null);
\copy tt_random_pw from 'random_passwords.txt';

DO LANGUAGE plpgsql
$$
DECLARE
        v_rand_pw text;
BEGIN

        FOR v_rand_pw IN SELECT pw FROM tt_random_pw LIMIT 10000
        LOOP

                PERFORM pwhash_crypt(v_rand_pw, pwhash_gen_salt('argon2id'));

        END LOOP;

END;
$$;

COMMIT;
