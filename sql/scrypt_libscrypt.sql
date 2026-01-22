-- ----------------------------------------------------
-- Test crypt() compatible interface pwhash_crypt()
-- ----------------------------------------------------

--
-- scrypt via libscrypt
--
SELECT pwhash_crypt('password', '$scrypt$ln=16,r=8,p=1$MTIzNDU2Nzg$NuB+vs2zc0fb2UzIRwwAV6ZWb3St8+X9IedYI1gQsoo') = '$scrypt$ln=16,r=8,p=1$MTIzNDU2Nzg$NuB+vs2zc0fb2UzIRwwAV6ZWb3St8+X9IedYI1gQsoo' AS hash;
