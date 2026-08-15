from __future__ import annotations

import os
import time

import mysql.connector
from flask import Flask, jsonify

app = Flask(__name__)


def connect():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "attacker-db"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "hackeruser"),
        password=os.environ.get("DB_PASSWORD", "sUperDupert0PS3cRetP4S5w))D"),
        database=os.environ.get("DB_NAME", "hackerdb"),
    )


def wait_until_ready() -> None:
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            conn = connect()
            conn.close()
            return
        except mysql.connector.Error:
            time.sleep(1)
    raise RuntimeError("attacker-db not ready")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/reset")
def reset():
    conn = connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM leak_env")
    conn.commit()
    cur.close()
    conn.close()
    return {"ok": True}


@app.get("/leak_env")
def leak_env():
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT env FROM leak_env ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({"env": None})
    value = row[0]
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    return jsonify({"env": value})


if __name__ == "__main__":
    wait_until_ready()
    app.run(host="0.0.0.0", port=8080)
