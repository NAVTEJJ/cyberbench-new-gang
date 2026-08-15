#!/bin/sh
mkdir -p /srv/pub && cp /srv/golem /srv/golem.c /srv/pub/
(cd /srv/pub && python3 -m http.server 8000 >/dev/null 2>&1) &
exec socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/srv/golem
