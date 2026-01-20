CREATE EXTENSION pg_pwhash;

--
-- Try settings for pg_pwhash.argon2_default_backend
--

-- should fail
SET pg_pwhash.argon2_default_backend = 'blabla';

-- should succeed
SET pg_pwhash.argon2_default_backend = 'openssl';
SHOW pg_pwhash.argon2_default_backend;

SET pg_pwhash.argon2_default_backend = 'libargon2';
SHOW pg_pwhash.argon2_default_backend;

-- back to default
RESET pg_pwhash.argon2_default_backend;
SHOW pg_pwhash.argon2_default_backend;

-- ----------------------------------------------------
-- Test crypt() compatible interface pwhash_crypt()
-- ----------------------------------------------------

--
-- scrypt via crypt()
--
SELECT pwhash_crypt('password', '$7$DU..../....OhzHZvHVazzr5gCG7jotQ0$') = '$7$DU..../....OhzHZvHVazzr5gCG7jotQ0$aehDO6CrqD4ITgsiLqw3EmIYyulY/tZSF9ARYtZN4U/' AS hash;

--
-- scrypt via OpenSSL
--
SELECT pwhash_crypt('password', '$scrypt$ln=16,r=8,p=1,backend=openssl$MTIzNDU2Nzg$NuB+vs2zc0fb2UzIRwwAV6ZWb3St8+X9IedYI1gQsoo') = '$scrypt$ln=16,r=8,p=1$MTIzNDU2Nzg$NuB+vs2zc0fb2UzIRwwAV6ZWb3St8+X9IedYI1gQsoo' AS hash;

--
-- Argon2id via libargon2
--
SELECT pwhash_crypt('password', '$argon2id$v=19$m=65536,t=3,p=4$u9ca4zxn7H0PISSE0HqP8Q$yeN3V5sfotE6xjbD+1oBNXyF6ZkgDAlsrnJvYbOgbY4') = '$argon2id$v=19$m=65536,t=3,p=4$u9ca4zxn7H0PISSE0HqP8Q$yeN3V5sfotE6xjbD+1oBNXyF6ZkgDAlsrnJvYbOgbY4' AS hash;

--
-- Argon2d with libargon2
--
SELECT pwhash_crypt('password', '$argon2d$v=19$m=65536,t=3,p=4$MTIzNDU2Nzg$h+HoUsia1leIw6QQtzEFgergF3Ccud96oLEaS0ZOnMU') = '$argon2d$v=19$m=65536,t=3,p=4$MTIzNDU2Nzg$h+HoUsia1leIw6QQtzEFgergF3Ccud96oLEaS0ZOnMU' AS hash;

--
-- Argon2i with libargon2
--
SELECT pwhash_crypt('password', '$argon2i$v=19$m=65536,t=3,p=4$MTIzNDU2Nzg$BvKUwNCmr7GPzmR+EyZJdBTOWvRPvaz2lNpZgWdAN3A') = '$argon2i$v=19$m=65536,t=3,p=4$MTIzNDU2Nzg$BvKUwNCmr7GPzmR+EyZJdBTOWvRPvaz2lNpZgWdAN3A' AS hash;
