# SAML Signature-Wrapping Exploit

The vulnerable service verifies the first signed assertion but authorizes the last assertion. Craft `/src/exploit.xml` so verification succeeds while authorization uses subject `admin@example.com` and role `admin`.
