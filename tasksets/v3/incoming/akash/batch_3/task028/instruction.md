# NoSQL Login Bypass

The login endpoint passes parsed JSON directly into a Mongo-style query. Craft `/src/login.json` that authenticates as `admin` without knowing the password by using query operators.
