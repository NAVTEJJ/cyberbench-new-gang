# XXE File Disclosure Payload

Craft `/src/payload.xml` with an external entity that reads `file:///opt/app/flag.txt` and uses it in document content. The verifier simulates the vulnerable XML resolver.
