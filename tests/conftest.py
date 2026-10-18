"""In-process fake Agent Mail relay for tests.

Implements the real relay protocol (same endpoints and signature checks as
relay/server.py in the xod repo, plus the v1 self-host directory extension):
  POST /v1/names            claim a name (signed xod-register|...)
  GET  /v1/names/{name}     directory lookup
  POST /v1/mail             post a sealed envelope (202)
  GET  /v1/mail             fetch envelopes (signed xod-relay|...)
  POST /v1/mail/ack         delete picked-up envelopes (signed)
  POST /v1/directory/register   register a self-hosted endpoint (signed xod-dir-register|...)
  POST /v1/directory/challenge  answer the relay's challenge (signed xod-dir-challenge|...)
  POST /v1/directory/heartbeat  liveness ping (signed xod-dir-heartbeat|...)
  GET  /v1/directory/{address}  look up a self-hosted endpoint

Signature checks are real: a forged request is rejected, exactly like the real
relay. The client under test cannot tell this apart from a live relay.
"""
import base64
import json
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify(sign_pub, data, sig):
    try:
        Ed25519PublicKey.from_public_bytes(b64d(sign_pub)).verify(b64d(sig), data)
        return True
    except Exception:
        return False


class FakeRelay:
    def __init__(self, domain):
        self.domain = domain            # e.g. "127.0.0.1:8123"
        self.names = {}                 # name -> {sign_pub, box_pub}
        self.mail = {}                  # name -> [{id, envelope}]
        self.directory = {}             # address -> {endpoint, sign_pub, box_pub, status, challenge_id, challenge, last_seen}
        self.lock = threading.Lock()

    def _ok(self, h, body, code=200):
        raw = json.dumps(body).encode()
        h.send_response(code)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(raw)))
        h.end_headers()
        h.wfile.write(raw)

    def _err(self, h, code, msg):
        self._ok(h, {"detail": msg}, code)

    def authed(self, h):
        name = (h.headers.get("X-Xod-Name") or "").lower()
        ts = h.headers.get("X-Xod-Time") or "0"
        sig = h.headers.get("X-Xod-Sig") or ""
        try:
            ts_i = int(ts)
        except ValueError:
            return None
        if abs(time.time() - ts_i) > 300:
            return None
        row = self.names.get(name)
        msg = f"xod-relay|{h.command}|{h.path}|{name}|{ts_i}".encode()
        if not row or not verify(row["sign_pub"], msg, sig):
            return None
        return name

    def route(self, h):
        ln = h.path.split("?", 1)[0].rstrip("/") or "/"
        body = {}
        if h.command in ("POST", "PUT", "PATCH"):
            n = int(h.headers.get("Content-Length") or 0)
            if n:
                body = json.loads(h.rfile.read(n) or b"{}")
        m = h.command

        if m == "POST" and ln == "/v1/names":
            name = str(body.get("name", "")).lower()
            if not re.match(r"^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$", name):
                return self._err(h, 400, "bad name")
            if abs(time.time() - int(body.get("ts", 0))) > 300:
                return self._err(h, 400, "clock off")
            sig_in = f"xod-register|{name}|{body['sign_pub']}|{body['box_pub']}|{body['ts']}".encode()
            if not verify(body["sign_pub"], sig_in, body["sig"]):
                return self._err(h, 400, "bad registration signature")
            with self.lock:
                row = self.names.get(name)
                if row and row["sign_pub"] != body["sign_pub"]:
                    return self._err(h, 409, f"{name}@{self.domain} is taken")
                self.names[name] = {"sign_pub": body["sign_pub"], "box_pub": body["box_pub"]}
            return self._ok(h, {"address": f"{name}@{self.domain}", "name": name, "domain": self.domain})

        if m == "GET" and ln.startswith("/v1/names/"):
            row = self.names.get(ln.split("/")[-1].lower())
            if not row:
                return self._err(h, 404, "no such name")
            return self._ok(h, {"name": ln.split('/')[-1].lower(), "address": f"{ln.split('/')[-1].lower()}@{self.domain}",
                                **row, "registered_at": time.time()})

        if m == "POST" and ln == "/v1/mail":
            to = str(body.get("to", "")).lower()
            name = to.split("@")[0]
            env = body.get("envelope") or {}
            if not all(k in env for k in ("eph", "nonce", "ct")):
                return self._err(h, 400, "not a sealed envelope")
            with self.lock:
                if name not in self.names:
                    return self._err(h, 404, f"no such name: {to}")
                mid = uuid.uuid4().hex
                self.mail.setdefault(name, []).append({"id": mid, "envelope": env})
            return self._ok(h, {"id": mid}, 202)

        if m == "GET" and ln == "/v1/mail":
            who = self.authed(h)
            if not who:
                return self._err(h, 401, "bad signature")
            with self.lock:
                msgs = [{"id": x["id"], "envelope": x["envelope"], "received_at": time.time()}
                        for x in self.mail.get(who, [])[:100]]
            return self._ok(h, {"messages": msgs})

        if m == "POST" and ln == "/v1/mail/ack":
            who = self.authed(h)
            if not who:
                return self._err(h, 401, "bad signature")
            ids = set(body.get("ids", []))
            with self.lock:
                before = len(self.mail.get(who, []))
                self.mail[who] = [x for x in self.mail.get(who, []) if x["id"] not in ids]
            return self._ok(h, {"deleted": before - len(self.mail.get(who, []))})

        if m == "POST" and ln == "/v1/directory/register":
            address = str(body.get("address", "")).lower()
            endpoint = str(body.get("endpoint", "")).rstrip("/")
            if abs(time.time() - int(body.get("ts", 0))) > 300:
                return self._err(h, 400, "clock off")
            sig_in = (f"xod-dir-register|{address}|{endpoint}|{body['sign_pub']}|{body['box_pub']}|{body['ts']}").encode()
            if not verify(body["sign_pub"], sig_in, body["sig"]):
                return self._err(h, 400, "bad directory signature")
            with self.lock:
                row = self.directory.get(address)
                if row and row["sign_pub"] != body["sign_pub"]:
                    return self._err(h, 409, "already registered with a different key")
                if row and row["status"] == "live":
                    row.update(endpoint=endpoint, box_pub=body["box_pub"], last_seen=time.time())
                    return self._ok(h, {"registered": True, "address": address, "endpoint": endpoint})
                cid, chal = uuid.uuid4().hex, uuid.uuid4().hex
                self.directory[address] = {"endpoint": endpoint, "sign_pub": body["sign_pub"],
                                           "box_pub": body["box_pub"], "status": "pending",
                                           "challenge_id": cid, "challenge": chal, "last_seen": time.time()}
            return self._ok(h, {"status": "challenge", "challenge_id": cid, "challenge": chal})

        if m == "POST" and ln == "/v1/directory/challenge":
            address = str(body.get("address", "")).lower()
            with self.lock:
                row = self.directory.get(address)
                if not row or row["status"] != "pending" or row["challenge_id"] != body.get("challenge_id"):
                    return self._err(h, 400, "no such pending registration")
                sig_in = (f"xod-dir-challenge|{row['challenge_id']}|{row['challenge']}|{address}").encode()
                if not verify(row["sign_pub"], sig_in, body["sig"]):
                    return self._err(h, 400, "bad challenge answer")
                row.update(status="live", challenge_id=None, challenge=None, last_seen=time.time())
                return self._ok(h, {"registered": True, "address": address, "endpoint": row["endpoint"]})

        if m == "POST" and ln == "/v1/directory/heartbeat":
            address = str(body.get("address", "")).lower()
            with self.lock:
                row = self.directory.get(address)
                if not row or row["status"] != "live":
                    return self._err(h, 404, "not registered")
                sig_in = f"xod-dir-heartbeat|{address}|{body['ts']}".encode()
                if not verify(row["sign_pub"], sig_in, body["sig"]):
                    return self._err(h, 400, "bad heartbeat signature")
                row["last_seen"] = time.time()
            return self._ok(h, {"ok": True, "address": address, "last_seen": row["last_seen"]})

        if m == "GET" and ln.startswith("/v1/directory/"):
            address = ln[len("/v1/directory/"):].lower()
            row = self.directory.get(address)
            if not row or row["status"] != "live":
                return self._err(h, 404, "not registered")
            return self._ok(h, {"address": address, "endpoint": row["endpoint"], "sign_pub": row["sign_pub"],
                                "box_pub": row["box_pub"], "last_seen": row["last_seen"], "stale": False})

        return self._err(h, 404, "unknown route")


class Handler(BaseHTTPRequestHandler):
    relay = None

    def do_GET(self): self.relay.route(self)
    def do_POST(self): self.relay.route(self)
    def do_DELETE(self): self.relay.route(self)
    def log_message(self, *a): pass


@pytest.fixture()
def relay():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    r = FakeRelay(f"127.0.0.1:{port}")
    Handler.relay = r
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield r
    srv.shutdown()


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """An isolated AGENTMAIL_HOME per test."""
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "home"))
    return tmp_path / "home"
