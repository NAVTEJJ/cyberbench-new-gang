# Unicode Path Traversal Bypass

A file API validates before repeated decoding and Unicode NFKC normalization. Craft `/src/path.txt` that ultimately resolves to `../secrets/flag.txt` while initially appearing to be an allowed `.txt` path under `public/`.
