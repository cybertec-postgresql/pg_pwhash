-- Should succeed
SELECT pwhash_scrypt_crypt('password', '$7$DU..../....OhzHZvHVazzr5gCG7jotQ0$aehDO6CrqD4ITgsiLqw3EmIYyulY/tZSF9ARYtZN4U/') = '$7$DU..../....OhzHZvHVazzr5gCG7jotQ0$aehDO6CrqD4ITgsiLqw3EmIYyulY/tZSF9ARYtZN4U/';

-- Should fail, obscure salt
SELECT pwhash_scrypt_crypt('password', '$7$abcdefghijkl');

-- ----------------------------------------------------
-- Test crypt() compatible interface pwhash_crypt()
-- ----------------------------------------------------

--
-- scrypt via crypt()
--
SELECT pwhash_crypt('password', '$7$DU..../....OhzHZvHVazzr5gCG7jotQ0$') = '$7$DU..../....OhzHZvHVazzr5gCG7jotQ0$aehDO6CrqD4ITgsiLqw3EmIYyulY/tZSF9ARYtZN4U/' AS hash;
