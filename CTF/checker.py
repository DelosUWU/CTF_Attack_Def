#!/usr/bin/env python3
import hashlib
import json
import os
import re
import secrets
import string
import sys
from enum import IntEnum
from pathlib import Path

import requests


TIMEOUT = 4
FLAG_RE = re.compile(r"^[A-Z0-9]{31}=$")
STATE_FILE = Path(__file__).with_name(".checker_flags.json")


class Verdict(IntEnum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110


class Down(Exception):
    pass


class Mumble(Exception):
    pass


class Corrupt(Exception):
    pass


def finish(verdict):
    print(verdict.name)
    raise SystemExit(int(verdict))


def random_flag():
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(31)) + "="


def password_for(username, flag):
    digest = hashlib.sha256(f"{username}:{flag}:patchboard".encode()).hexdigest()
    return "Pw!" + digest[:24]


def base_url(host, port):
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"http://{host}:{port}".rstrip("/")


def req(session, method, url, **kwargs):
    try:
        response = session.request(method, url, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise Down() from exc
    return response


def json_req(session, method, url, expected=None, **kwargs):
    response = req(session, method, url, **kwargs)
    if expected is not None and response.status_code not in expected:
        if response.status_code >= 500:
            raise Down()
        raise Mumble()
    try:
        return response.json()
    except ValueError as exc:
        raise Mumble() from exc


def register(session, base, username, password):
    response = req(
        session,
        "POST",
        f"{base}/api/register",
        json={"username": username, "email": f"{username}@team.local", "password": password},
    )
    if response.status_code not in (201, 409):
        if response.status_code >= 500:
            raise Down()
        raise Mumble()


def login(session, base, username, password):
    payload = json_req(
        session,
        "POST",
        f"{base}/api/login",
        expected={200},
        json={"username": username, "password": password},
    )
    if payload.get("user", {}).get("username") != username:
        raise Mumble()


def create_card(session, base, title, body):
    payload = json_req(
        session,
        "POST",
        f"{base}/api/cards",
        expected={201},
        json={"title": title, "body": body},
    )
    card_id = payload.get("id")
    receipt_code = payload.get("receipt_code")
    if not isinstance(card_id, int) or not receipt_code:
        raise Mumble()
    return card_id, receipt_code


def read_card(session, base, card_id):
    payload = json_req(session, "GET", f"{base}/api/cards/{card_id}", expected={200})
    card = payload.get("card")
    if not isinstance(card, dict):
        raise Mumble()
    return card


def save_flag(flag_id, flag):
    state = []
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = []
    state = [item for item in state if item.get("flag_id") != flag_id]
    state.append({"flag_id": flag_id, "flag": flag})
    STATE_FILE.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")


def cmd_check(base):
    username = "check_" + secrets.token_hex(5)
    password = "Pw!" + secrets.token_hex(12)
    marker = "probe-" + secrets.token_hex(12)
    title = "handoff-" + secrets.token_hex(4)

    session = requests.Session()
    register(session, base, username, password)
    login(session, base, username, password)
    card_id, receipt = create_card(session, base, title, marker)

    card = read_card(session, base, card_id)
    if card.get("body") != marker or card.get("title") != title:
        raise Corrupt()

    search = json_req(
        session,
        "GET",
        f"{base}/api/cards/search",
        expected={200},
        params={"q": title[:8]},
    )
    found = any(item.get("id") == card_id and marker in item.get("preview", "") for item in search.get("cards", []))
    if not found:
        raise Mumble()

    receipt_payload = json_req(
        requests.Session(),
        "GET",
        f"{base}/api/cards/{card_id}/receipt",
        expected={200},
        params={"code": receipt},
    )
    if receipt_payload.get("card", {}).get("body") != marker:
        raise Mumble()

    docs = req(requests.Session(), "GET", f"{base}/api/library", params={"doc": "onboarding.txt"})
    if docs.status_code != 200 or "PatchBoard onboarding" not in docs.text:
        raise Mumble()


def cmd_put(base, flag):
    if not FLAG_RE.fullmatch(flag):
        raise Mumble()

    username = "u_" + hashlib.sha1(f"{flag}:{secrets.token_hex(8)}".encode()).hexdigest()[:16]
    password = password_for(username, flag)
    session = requests.Session()
    register(session, base, username, password)
    login(session, base, username, password)
    card_id, _ = create_card(session, base, "sealed-" + secrets.token_hex(4), flag)
    flag_id = f"{username}:{card_id}"
    save_flag(flag_id, flag)
    print(flag_id)
    raise SystemExit(int(Verdict.OK))


def cmd_get(base, flag_id, flag):
    if ":" not in flag_id or not FLAG_RE.fullmatch(flag):
        raise Corrupt()
    username, raw_card_id = flag_id.split(":", 1)
    if not raw_card_id.isdigit():
        raise Corrupt()

    session = requests.Session()
    login(session, base, username, password_for(username, flag))
    card = read_card(session, base, int(raw_card_id))
    if card.get("body") != flag:
        raise Corrupt()


def cmd_get_flags():
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    for item in state:
        flag = item.get("flag")
        if isinstance(flag, str) and FLAG_RE.fullmatch(flag):
            print(flag)


def parse_cli(argv):
    commands = {"check", "put", "get", "get_flags"}
    if len(argv) < 4:
        raise ValueError

    if argv[1] in commands:
        command, host, port = argv[1], argv[2], argv[3]
        rest = argv[4:]
    else:
        host, port, command = argv[1], argv[2], argv[3]
        rest = argv[4:]

    if command not in commands:
        raise ValueError
    return command, base_url(host, port), rest


def main(argv):
    try:
        command, base, rest = parse_cli(argv)
    except ValueError:
        print("Usage: checker.py <ip> <port> <check|put|get|get_flags> [flag_id] [flag]", file=sys.stderr)
        raise SystemExit(int(Verdict.CHECKER_ERROR))

    try:
        if command == "check":
            cmd_check(base)
            finish(Verdict.OK)
        if command == "put":
            flag = rest[0] if rest else random_flag()
            cmd_put(base, flag)
        if command == "get":
            if len(rest) < 2:
                raise Corrupt()
            cmd_get(base, rest[0], rest[1])
            finish(Verdict.OK)
        if command == "get_flags":
            cmd_get_flags()
            raise SystemExit(0)
    except Down:
        finish(Verdict.DOWN)
    except Corrupt:
        finish(Verdict.CORRUPT)
    except Mumble:
        finish(Verdict.MUMBLE)
    except requests.RequestException:
        finish(Verdict.DOWN)


if __name__ == "__main__":
    main(sys.argv)
