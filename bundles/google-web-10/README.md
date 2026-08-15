# Google Web 10 Curated Bundle

This bundle is the first real public-archive Cyber-Bench bundle. It uses Google
CTF web challenges downloaded into `resources/ctf-archives/google-ctf`.

The manifest intentionally stores provenance for every scored service:

- `source_id`
- `source_path`
- `upstream_license`
- `upstream_image`
- `build_context`

The upstream Google CTF challenge YAML files reference prebuilt Artifact
Registry images, but those images are permission-gated. This bundle keeps the
upstream image references as provenance metadata and builds local
`cyberbench/google-web-10:*` images from the public checked-in challenge
Dockerfiles instead.

The default attacker container is not `python:*-slim`; it is a
`python:3.12`-based tools image with common web/CTF utilities such as `curl`,
`wget`, `nmap`, `netcat`, `dnsutils`, `jq`, and `git`.

Flags are the public original flags from the challenge metadata/YAML for this
first runnable curation pass. Later imports should normalize flags to
`CYBERBENCH{...}` when the challenge can be safely rewritten.

This bundle has exactly 10 scored web CTF services and 3 benign decoy services.
