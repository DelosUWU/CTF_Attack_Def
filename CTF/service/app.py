import base64
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import traceback
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
LIBRARY_DIR = BASE_DIR / "library"
DATA_DIR = Path(os.environ.get("LEDGER_DATA", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "ledger.db"

PORT = int(os.environ.get("PORT", "8080"))
SESSION_COOKIE = "patchboard_session"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def password_hash(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def make_receipt_code(username, card_id):
    raw = f"{username}:{card_id}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:12]


def db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                receipt_code TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS card_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_id INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def row_to_dict(row):
    return {key: row[key] for key in row.keys()}


def catalog_path_from_query(query):
    raw = query.replace("\\", "/")
    if ".." not in raw:
        return None

    if raw.startswith(("http://", "https://")):
        path = unquote(urlparse(raw).path).lstrip("/")
    elif raw.startswith(("http:/", "https:/", "http", "https")):
        traversal_at = raw.find("..")
        path = raw[traversal_at:] if traversal_at >= 0 else ""
    else:
        return None

    return (LIBRARY_DIR / path).resolve()


def catalog_entry_preview(path):
    try:
        if path.is_dir():
            entries = []
            for child in sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))[:40]:
                suffix = "/" if child.is_dir() else ""
                entries.append(f"{child.name}{suffix}")
            return "\n".join(entries) or "(empty directory)"

        size = path.stat().st_size
        return f"{path.name} ({size} bytes)"
    except OSError:
        return "(cannot read directory)"


class PatchBoardHandler(BaseHTTPRequestHandler):
    server_version = "PatchBoard/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        self.path_only = unquote(parsed.path)
        self.query = parse_qs(parsed.query, keep_blank_values=True)

        try:
            if self.path_only == "/" or self.path_only.startswith("/static/"):
                return self.serve_static()

            if self.path_only.startswith("/api/"):
                return self.route_api(method)

            self.send_json(404, {"error": "not_found"})
        except ClientError as exc:
            self.send_json(exc.status, {"error": exc.code, "message": exc.message})
        except Exception:
            traceback.print_exc()
            self.send_json(500, {"error": "internal_error"})

    def serve_static(self):
        if self.path_only == "/":
            target = STATIC_DIR / "index.html"
        else:
            relative = self.path_only.removeprefix("/static/")
            target = (STATIC_DIR / relative).resolve()
            if not str(target).startswith(str(STATIC_DIR.resolve())):
                raise ClientError(404, "not_found", "Static file was not found")

        if not target.is_file():
            raise ClientError(404, "not_found", "Static file was not found")

        body = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def route_api(self, method):
        if method == "POST" and self.path_only == "/api/register":
            return self.api_register()
        if method == "POST" and self.path_only == "/api/login":
            return self.api_login()
        if method == "POST" and self.path_only == "/api/logout":
            return self.api_logout()
        if method == "GET" and self.path_only == "/api/me":
            return self.api_me()

        if method == "GET" and self.path_only == "/api/cards":
            return self.api_list_cards()
        if method == "POST" and self.path_only == "/api/cards":
            return self.api_create_card()
        if method == "GET" and self.path_only == "/api/cards/search":
            return self.api_search_cards()

        card_receipt = re.fullmatch(r"/api/cards/(\d+)/receipt", self.path_only)
        if method == "GET" and card_receipt:
            return self.api_card_receipt(int(card_receipt.group(1)))

        card_detail = re.fullmatch(r"/api/cards/(\d+)", self.path_only)
        if method == "GET" and card_detail:
            return self.api_card_detail(int(card_detail.group(1)))

        if method == "GET" and self.path_only == "/api/library":
            return self.api_library()

        self.send_json(404, {"error": "not_found"})

    def api_register(self):
        data = self.read_json()
        username = str(data.get("username", "")).strip()
        email = str(data.get("email", "")).strip()
        password = str(data.get("password", ""))

        if not USERNAME_RE.fullmatch(username):
            raise ClientError(400, "bad_username", "Username must be 3-24 letters, digits or underscores")
        if len(password) < 6 or len(password) > 128:
            raise ClientError(400, "bad_password", "Password length must be between 6 and 128")
        if "@" not in email or len(email) > 120:
            raise ClientError(400, "bad_email", "Email is invalid")

        try:
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO users(username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, password_hash(password), now_iso()),
                )
                user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            raise ClientError(409, "user_exists", "Username is already taken")

        self.send_json(201, {"id": user_id, "username": username})

    def api_login(self):
        data = self.read_json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or user["password_hash"] != password_hash(password):
                raise ClientError(403, "bad_login", "Invalid username or password")

            token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
            conn.execute(
                "INSERT INTO sessions(token, user_id, created_at) VALUES (?, ?, ?)",
                (token, user["id"], int(time.time())),
            )

        payload = {"id": user["id"], "username": user["username"], "email": user["email"]}
        self.send_json(200, {"user": payload}, cookies={SESSION_COOKIE: token})

    def api_logout(self):
        token = self.get_session_token()
        if token:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self.send_json(200, {"ok": True}, cookies={SESSION_COOKIE: ""})

    def api_me(self):
        user = self.require_user()
        self.send_json(200, {"user": user})

    def api_create_card(self):
        user = self.require_user()
        data = self.read_json()
        title = str(data.get("title", "")).strip()
        body = str(data.get("body", ""))

        if not title or len(title) > 90:
            raise ClientError(400, "bad_title", "Title length must be between 1 and 90")
        if not body or len(body) > 5000:
            raise ClientError(400, "bad_body", "Body length must be between 1 and 5000")

        with db() as conn:
            cur = conn.execute(
                "INSERT INTO cards(owner_id, title, body, created_at) VALUES (?, ?, ?, ?)",
                (user["id"], title, body, now_iso()),
            )
            card_id = cur.lastrowid
            receipt_code = make_receipt_code(user["username"], card_id)
            conn.execute("UPDATE cards SET receipt_code = ? WHERE id = ?", (receipt_code, card_id))
            conn.execute(
                "INSERT INTO card_events(card_id, actor, action, created_at) VALUES (?, ?, ?, ?)",
                (card_id, user["username"], "created", now_iso()),
            )

        self.send_json(
            201,
            {
                "id": card_id,
                "title": title,
                "receipt_code": receipt_code,
                "receipt_url": f"/api/cards/{card_id}/receipt?code={receipt_code}",
            },
        )

    def api_list_cards(self):
        user = self.require_user()
        with db() as conn:
            rows = conn.execute(
                """
                SELECT id, title, substr(body, 1, 100) AS preview, receipt_code, created_at
                FROM cards
                WHERE owner_id = ?
                ORDER BY id DESC
                LIMIT 30
                """,
                (user["id"],),
            ).fetchall()
        self.send_json(200, {"cards": [row_to_dict(row) for row in rows]})

    def api_card_detail(self, card_id):
        user = self.require_user()
        with db() as conn:
            row = conn.execute(
                """
                SELECT cards.id, users.username AS owner, cards.title, cards.body,
                       cards.receipt_code, cards.created_at
                FROM cards
                JOIN users ON users.id = cards.owner_id
                WHERE cards.id = ? AND cards.owner_id = ?
                """,
                (card_id, user["id"]),
            ).fetchone()

        if not row:
            raise ClientError(404, "not_found", "Card was not found")
        self.send_json(200, {"card": row_to_dict(row)})

    def api_card_receipt(self, card_id):
        code = self.query.get("code", [""])[0]
        with db() as conn:
            row = conn.execute(
                """
                SELECT cards.id, users.username AS owner, cards.title, cards.body,
                       cards.receipt_code, cards.created_at
                FROM cards
                JOIN users ON users.id = cards.owner_id
                WHERE cards.id = ?
                """,
                (card_id,),
            ).fetchone()

            if not row:
                raise ClientError(404, "not_found", "Receipt was not found")
            expected = make_receipt_code(row["owner"], row["id"])
            if code != expected:
                raise ClientError(404, "not_found", "Receipt was not found")

            conn.execute(
                "INSERT INTO card_events(card_id, actor, action, created_at) VALUES (?, ?, ?, ?)",
                (card_id, "receipt", "viewed", now_iso()),
            )

        self.send_json(200, {"card": row_to_dict(row)})

    def api_search_cards(self):
        user = self.require_user()
        q = self.query.get("q", [""])[0][:160]

        catalog_path = catalog_path_from_query(q)
        if catalog_path is not None:
            if not catalog_path.exists():
                raise ClientError(404, "not_found", "Indexed resource was not found")
            self.send_json(
                200,
                {
                    "cards": [
                        {
                            "id": 0,
                            "owner": "library-index",
                            "title": f"Index of {catalog_path}",
                            "preview": catalog_entry_preview(catalog_path),
                            "created_at": now_iso(),
                        }
                    ]
                },
            )
            return

        with db() as conn:
            sql = f"""
                SELECT cards.id, users.username AS owner, cards.title,
                       substr(cards.body, 1, 220) AS preview, cards.created_at
                FROM cards
                JOIN users ON users.id = cards.owner_id
                WHERE cards.owner_id = {int(user["id"])}
                  AND (cards.title LIKE '%{q}%' OR cards.body LIKE '%{q}%')
                ORDER BY cards.id DESC
                LIMIT 50
            """
            rows = conn.execute(sql).fetchall()

        self.send_json(200, {"cards": [row_to_dict(row) for row in rows]})

    def api_library(self):
        doc = self.query.get("doc", ["onboarding.txt"])[0]
        target = os.path.join(str(LIBRARY_DIR), doc)

        if not os.path.isfile(target):
            raise ClientError(404, "not_found", "Library document was not found")

        body = Path(target).read_bytes()
        content_type = mimetypes.guess_type(target)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64 * 1024:
            raise ClientError(413, "too_large", "Request body is too large")

        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise ClientError(400, "bad_json", "Request body must be JSON")

        if not isinstance(data, dict):
            raise ClientError(400, "bad_json", "Request body must be a JSON object")
        return data

    def get_session_token(self):
        header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(header)
        except cookies.CookieError:
            return None
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def current_user(self):
        token = self.get_session_token()
        if not token:
            return None
        with db() as conn:
            row = conn.execute(
                """
                SELECT users.id, users.username, users.email
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token = ?
                """,
                (token,),
            ).fetchone()
        return row_to_dict(row) if row else None

    def require_user(self):
        user = self.current_user()
        if not user:
            raise ClientError(401, "unauthorized", "Authentication is required")
        return user

    def send_json(self, status, payload, cookies=None):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookies:
            for name, value in cookies.items():
                if value:
                    self.send_header("Set-Cookie", f"{name}={value}; Path=/; SameSite=Lax")
                else:
                    self.send_header(
                        "Set-Cookie",
                        f"{name}=; Path=/; Max-Age=0; SameSite=Lax",
                    )
        self.end_headers()
        self.wfile.write(body)


class ClientError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def main():
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), PatchBoardHandler)
    print(f"PatchBoard is listening on 0.0.0.0:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
