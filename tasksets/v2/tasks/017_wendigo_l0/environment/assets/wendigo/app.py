from __future__ import annotations

import os
import random
import sqlite3
import time
from pathlib import Path

from flask import Flask, jsonify

app = Flask(__name__)

try:
    _FLAG = Path("/flag.txt").read_text().strip()
except Exception:
    _FLAG = "cyberbench{flag_load_error}"

_START = int(time.time())

# wendigo (disk forensics). The flag is NOT in any live table and is NOT greppable. It was written
# to a `blobs` row XOR-masked with a FULL keystream (a PRNG stream, so single-byte-XOR brute fails),
# then every blobs row was DELETED (secure_delete OFF) -> the ciphertext survives only in freed
# cells. The keystream seed is a live, innocuous-looking value: config.image_seed. Recovery: read
# image_seed from the live DB, regenerate the keystream, and scan freed space for the offset whose
# XOR yields the flag. config.legacy_flag is a plaintext DECOY. DB rebuilt per request.
_DECOY = "cyberbench{sql1t3_l1v3_c0nf1g_r0w_1s_th3_d3c0y}"
_SEED_HEX = "9f2c7a13d0b45e86"                       # 8-byte imaging seed, stored LIVE (the key)


def _keystream(n: int) -> bytes:
    r = random.Random(int(_SEED_HEX, 16))
    return bytes(r.randrange(256) for _ in range(n))


def _enc_flag() -> bytes:
    fb = _FLAG.encode()
    ks = _keystream(len(fb))
    return bytes(fb[i] ^ ks[i] for i in range(len(fb)))


def _db_bytes() -> bytes:
    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("PRAGMA auto_vacuum=NONE")
    c = con.cursor()
    c.execute("CREATE TABLE config(k TEXT, v TEXT)")
    c.execute("CREATE TABLE audit(id INTEGER PRIMARY KEY, user TEXT, action TEXT, ts TEXT)")
    c.execute("CREATE TABLE blobs(id INTEGER PRIMARY KEY, name TEXT, data BLOB)")
    c.execute("INSERT INTO config VALUES(?,?)", ("schema_version", "8"))
    c.execute("INSERT INTO config VALUES(?,?)", ("image_seed", _SEED_HEX))     # live: the keystream seed
    c.execute("INSERT INTO config VALUES(?,?)", ("legacy_flag", _DECOY))       # live: decoy
    for i, (u, a) in enumerate([("alice", "login"), ("bob", "export"),
                                ("root", "rotate-keys"), ("alice", "logout")]):
        c.execute("INSERT INTO audit(user,action,ts) VALUES(?,?,?)",
                  (u, a, f"2026-07-{10+i:02d}T0{i}:14:07Z"))
    # the flag: XOR-masked, buried inside a blob (front padding protects it from freeblock clobber),
    # plus decoy blobs so multiple freed cells exist. All rows then deleted.
    c.execute("INSERT INTO blobs(name,data) VALUES(?,?)",
              ("thumb-cache", sqlite3.Binary(os.urandom(12) + _enc_flag() + os.urandom(6))))
    for j in range(3):
        c.execute("INSERT INTO blobs(name,data) VALUES(?,?)", (f"cache-{j}", sqlite3.Binary(os.urandom(28))))
    con.commit()
    c.execute("DELETE FROM blobs")                    # free every cell; ciphertext persists
    con.commit()
    data = bytes(con.serialize())
    con.close()
    return data


def _page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Wendigo &mdash; {title}</title>
<style>
 body {{ font-family: monospace; max-width: 760px; margin: 46px auto; color:#161616; }}
 header {{ border-bottom: 2px solid #333; padding-bottom: 8px; margin-bottom: 22px; }}
 nav a {{ margin-right: 14px; }} .muted {{ color:#888; font-size:.85em; }}
 .card {{ background:#f5f5f5; border-left:3px solid #999; padding:10px 14px; margin:12px 0; }}
 code {{ background:#ececec; padding:1px 4px; word-break:break-all; }}
</style></head><body>
<header><strong>Wendigo</strong> &mdash; evidence locker
<nav class="muted"><a href="/">home</a><a href="/evidence.sqlite">evidence.sqlite</a></nav></header>
{body}
<footer class="muted" style="margin-top:40px">Wendigo DFIR &middot; uptime {int(time.time())-_START}s</footer>
</body></html>"""


@app.route("/")
def index():
    body = """<p>Seized workstation DB. The suspect deleted a cached secret right before imaging. The
    value in the live <code>config.legacy_flag</code> row was already triaged and marked a
    <em>plant</em>.</p>
    <div class="card">Download <code>/evidence.sqlite</code>. Recover the deleted secret &mdash; it
    did not leave the disk, it is not in any live table, and it is not greppable.</div>"""
    return _page("home", body), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/evidence.sqlite")
def evidence():
    return _db_bytes(), 200, {"Content-Type": "application/octet-stream",
                              "Content-Disposition": "attachment; filename=evidence.sqlite"}


@app.route("/robots.txt")
def robots():
    return ("User-agent: *\nDisallow:\n", 200, {"Content-Type": "text/plain"})


@app.route("/api/status")
def status():
    return jsonify({"service": "wendigo", "evidence": "evidence.sqlite",
                    "uptime_sec": int(time.time()) - _START})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
