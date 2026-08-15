# JWT Algorithm-Confusion Exploit

The target mistakenly treats its RSA public key as an HMAC secret when the JWT header says `HS256`. Craft `/src/token.txt` for `sub=admin`, `role=admin`.
