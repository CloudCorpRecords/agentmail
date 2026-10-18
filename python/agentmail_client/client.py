"""
Agent Mail client: claim an address, look up contacts, send and receive sealed messages.

Everything lives under AGENTMAIL_HOME (default ~/.agentmail):
  keys.json    the identity's private keys (Ed25519 + X25519), file mode 0600
  config.json  claimed address, relay domain, last check state
  store.json   contacts (pinned keys, trust) and messages

The relay only ever sees names, envelope sizes and pickup times. It cannot read
messages or tell who sent them. See mail_crypto.py for the encryption.
"""
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from . import mail_crypto as mc

ADDRESS_RE = re.compile(r"^([a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)@([a-z0-9.-]+(?::\d{2,5})?)$")
TRUST = ("unknown", "known", "mine", "blocked")
MAX_RECIPIENTS = 20
MAX_TEXT = 20000
MAX_SUBJECT = 200


class MailError(Exception):
    pass


# ---------------------------------------------------------------- local state

def home() -> Path:
    return Path(os.environ.get("AGENTMAIL_HOME") or Path.home() / ".agentmail")


def _paths():
    h = home()
    h.mkdir(parents=True, exist_ok=True)
    return h / "keys.json", h / "config.json", h / "store.json"


def _load(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _save(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True))
    if path.name == "keys.json":
        os.chmod(path, 0o600)


def identity(create: bool = False) -> Optional[mc.Identity]:
    keys_path, _, _ = _paths()
    keys = _load(keys_path, {})
    if keys.get("sign") and keys.get("box"):
        return mc.Identity.from_secrets(keys["sign"], keys["box"])
    if not create:
        return None
    ident = mc.Identity.new()
    s, b = ident.secrets()
    _save(keys_path, {"sign": s, "box": b})
    return ident


def config() -> Dict[str, Any]:
    _, cfg_path, _ = _paths()
    return _load(cfg_path, {})


def save_config(cfg: Dict[str, Any]) -> None:
    _, cfg_path, _ = _paths()
    _save(cfg_path, cfg)


def store() -> Dict[str, Any]:
    _, _, store_path = _paths()
    return _load(store_path, {"contacts": {}, "messages": {}})


def save_store(data: Dict[str, Any]) -> None:
    _, _, store_path = _paths()
    _save(store_path, data)


# ---------------------------------------------------------------- relay

def default_relay() -> str:
    return (os.environ.get("AGENTMAIL_RELAY") or "").strip().lower()


def relay_base(domain: str) -> str:
    host = domain.split(":")[0]
    local = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local") or host.endswith(".localhost")
    return f"{'http' if local else 'https'}://{domain}"


def parse_address(address: str) -> tuple:
    m = ADDRESS_RE.match((address or "").strip().lower())
    if not m:
        raise MailError(f"{address!r} is not an agent address (like sam@post.example.com).")
    return m.group(1), m.group(2)


def _http(method: str, url: str, **kw) -> httpx.Response:
    # trust_env=False: proxy env vars in sandboxes/CI have broken no_proxy entries
    # that some httpx versions cannot parse, and relays are always contacted directly.
    with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as c:
        return c.request(method, url, **kw)


def _detail(r: httpx.Response) -> str:
    try:
        return r.json().get("detail") or r.text[:200]
    except Exception:
        return r.text[:200] or f"HTTP {r.status_code}"


def relay_of(address: str, explicit: Optional[str] = None) -> str:
    """The relay domain for an address. Explicit relay wins, then the address's domain."""
    if explicit:
        domain = explicit.strip().lower()
    else:
        _, domain = parse_address(address)
    return re.sub(r"^https?://", "", domain).strip("/")


# ---------------------------------------------------------------- setup: claim an address

def claim(name: str, relay: Optional[str] = None) -> Dict[str, Any]:
    """Claims name@relay with this machine's keys (made now if needed)."""
    relay = (relay or default_relay()).strip().lower()
    relay = re.sub(r"^https?://", "", relay).strip("/")
    name = (name or "").strip().lower()
    if not relay:
        return {"success": False, "error": "No relay given. Set AGENTMAIL_RELAY or pass --relay."}
    try:
        parse_address(f"{name}@{relay}")
    except MailError:
        return {"success": False, "error": "Names are 2-32 letters, numbers, dots, dashes or underscores."}
    ident = identity(create=True)
    try:
        r = _http("POST", f"{relay_base(relay)}/v1/names", json=mc.registration(ident, name))
    except httpx.HTTPError as e:
        return {"success": False, "error": f"Couldn't reach {relay}: {type(e).__name__}"}
    if r.status_code != 200:
        return {"success": False, "error": _detail(r)}
    address = r.json().get("address") or f"{name}@{relay}"
    cfg = config()
    cfg.update(name=name, domain=relay, address=address, registered_at=time.time(), last_error=None)
    save_config(cfg)
    return {"success": True, "address": address,
            "safety_number": mc.safety_number(ident.sign_pub, ident.box_pub)}


def status() -> Dict[str, Any]:
    cfg = config()
    ident = identity()
    st = store()
    out = {"set_up": bool(cfg.get("address") and ident), "address": cfg.get("address"),
           "relay": cfg.get("domain") or default_relay() or None,
           "last_check": cfg.get("last_check"), "last_error": cfg.get("last_error"),
           "unread": sum(1 for m in st["messages"].values()
                         if m["direction"] == "in" and not m.get("read")
                         and m.get("status") == "new"
                         and st["contacts"].get(m["peer"], {}).get("trust", "unknown") != "unknown")}
    if ident:
        out["safety_number"] = mc.safety_number(ident.sign_pub, ident.box_pub)
    return out


# ---------------------------------------------------------------- contacts and lookup

def lookup(address: str) -> Dict[str, Any]:
    name, domain = parse_address(address)
    try:
        r = _http("GET", f"{relay_base(domain)}/v1/names/{name}")
    except httpx.HTTPError as e:
        raise MailError(f"Couldn't reach {domain} ({type(e).__name__}).")
    if r.status_code == 404:
        raise MailError(f"There's no {address}.")
    if r.status_code != 200:
        raise MailError(_detail(r))
    d = r.json()
    return {"address": f"{name}@{domain}", "sign_pub": d["sign_pub"], "box_pub": d["box_pub"]}


def contacts() -> List[Dict[str, Any]]:
    return sorted(store()["contacts"].values(), key=lambda c: (c.get("trust") == "unknown", c["address"]))


def contact(address: str) -> Optional[Dict[str, Any]]:
    return store()["contacts"].get(address.strip().lower())


def _pin(address: str, sign_pub: str, box_pub: str, trust: str = "unknown") -> Dict[str, Any]:
    st = store()
    address = address.lower()
    if address not in st["contacts"]:
        now = time.time()
        st["contacts"][address] = {"address": address, "sign_pub": sign_pub, "box_pub": box_pub,
                                   "safety_number": mc.safety_number(sign_pub, box_pub), "trust": trust,
                                   "nickname": None, "verified": False, "first_seen": now, "updated_at": now}
        save_store(st)
    return st["contacts"][address]


def resolve(address: str, trust_if_new: str = "unknown") -> Dict[str, Any]:
    """The pinned contact for an address, looked up and pinned on first use. Raises if keys changed."""
    address = address.strip().lower()
    known = contact(address)
    if known and known["trust"] == "blocked":
        raise MailError(f"You've blocked {address}.")
    fresh = lookup(address)
    if known and known.get("sign_pub"):
        if (known["sign_pub"], known["box_pub"]) != (fresh["sign_pub"], fresh["box_pub"]):
            raise MailError(f"{address}'s keys have changed since you last talked. "
                            "Check their safety number with them before sending.")
        return known
    return _pin(address, fresh["sign_pub"], fresh["box_pub"], trust_if_new)


def set_trust(address: str, trust: str) -> bool:
    if trust not in TRUST:
        return False
    st = store()
    address = address.strip().lower()
    if address not in st["contacts"]:
        return False
    st["contacts"][address]["trust"] = trust
    st["contacts"][address]["updated_at"] = time.time()
    save_store(st)
    return True


def accept_new_keys(address: str) -> Dict[str, Any]:
    """After checking the new safety number with them: pin their new keys."""
    fresh = lookup(address)
    st = store()
    address = address.strip().lower()
    if address not in st["contacts"]:
        return {"success": False, "error": f"{address} is not a contact."}
    st["contacts"][address].update(sign_pub=fresh["sign_pub"], box_pub=fresh["box_pub"],
                                   safety_number=mc.safety_number(fresh["sign_pub"], fresh["box_pub"]),
                                   verified=False, updated_at=time.time())
    save_store(st)
    return {"success": True, "address": address,
            "safety_number": st["contacts"][address]["safety_number"]}


# ---------------------------------------------------------------- sending

def _recipients(to: Any) -> List[str]:
    items = to if isinstance(to, list) else re.split(r"[,\s;]+", str(to or ""))
    out = []
    for a in items:
        a = a.strip().lower()
        if a and a not in out:
            parse_address(a)
            out.append(a)
    if not out:
        raise MailError("No recipients. Give an agent address like sam@post.example.com.")
    if len(out) > MAX_RECIPIENTS:
        raise MailError(f"Up to {MAX_RECIPIENTS} recipients at a time.")
    return out


def send(to: Any, text: str, subject: str = "", kind: str = "message", thread: Optional[str] = None,
         in_reply_to: Optional[str] = None, msg_id: Optional[str] = None) -> Dict[str, Any]:
    """Seals and sends a message to each recipient now. The calling agent decides the policy."""
    cfg, ident = config(), identity()
    if not (cfg.get("address") and ident):
        raise MailError("No address claimed yet. Run claim first.")
    if not (text or "").strip():
        raise MailError("The message is empty.")
    recips = _recipients(to)
    thread = thread or uuid.uuid4().hex[:16]
    msg_id = msg_id or uuid.uuid4().hex
    message = {"id": msg_id, "thread": thread, "kind": kind if kind in ("message", "task_request", "reply") else "message",
               "subject": (subject or "")[:MAX_SUBJECT], "text": text[:MAX_TEXT],
               "in_reply_to": in_reply_to, "recipients": recips, "sent_at": int(time.time())}
    sent, errors = [], []
    for addr in recips:
        try:
            who = resolve(addr, trust_if_new="known")    # writing to someone makes them a contact
            env = mc.seal(ident, cfg["address"], addr, who["box_pub"], message)
            _, domain = parse_address(addr)
            r = _http("POST", f"{relay_base(domain)}/v1/mail", json={"to": addr, "envelope": env})
            if r.status_code != 202:
                raise MailError(_detail(r))
            sent.append(addr)
        except (MailError, httpx.HTTPError) as e:
            errors.append(f"{addr}: {e}")
    st = store()
    mid = f"out-{msg_id[:12]}"
    st["messages"][mid] = {"id": mid, "msg_id": msg_id, "thread": thread, "direction": "out",
                           "peer": recips[0], "recipients": recips, "kind": message["kind"],
                           "subject": message["subject"], "text": message["text"],
                           "status": "sent" if sent else "failed", "verified": True,
                           "problem": "; ".join(errors) or None, "in_reply_to": in_reply_to,
                           "created_at": time.time(), "read": True}
    save_store(st)
    if not sent:
        return {"success": False, "error": "; ".join(errors)}
    return {"success": True, "sent_to": sent, "errors": errors, "thread": thread, "msg_id": msg_id}


# ---------------------------------------------------------------- receiving

def _receive(ident: mc.Identity, my_address: str, envelope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    opened = mc.open_envelope(ident, my_address, envelope)
    msg, keys = opened["msg"], opened["keys"]
    sender = (msg.get("from") or "").lower()
    parse_address(sender)
    problem, status_v = None, "new"
    known = contact(sender)
    if not opened["signature_ok"]:
        problem, status_v = "The signature didn't check out, so this may not really be from them.", "held"
    elif known and known.get("sign_pub") and known["sign_pub"] != keys.get("sign"):
        problem, status_v = "Their keys changed since you last talked. Check their safety number before trusting this.", "held"
    else:
        try:
            directory = lookup(sender)
            if directory["sign_pub"] != keys.get("sign"):
                problem, status_v = "The keys inside don't match the sender's address, so it may be forged.", "held"
        except MailError as e:
            problem, status_v = f"Couldn't confirm the sender ({e}).", "held"
    if not known and status_v == "new":
        known = _pin(sender, keys["sign"], keys["box"], "unknown")
    trust = (known or {}).get("trust", "unknown")
    if trust == "blocked":
        status_v = "blocked"
    kind = msg.get("kind") if msg.get("kind") in ("message", "task_request", "reply") else "message"
    row_id = f"in-{uuid.uuid4().hex[:12]}"
    st = store()
    msg_id = str(msg.get("id") or uuid.uuid4().hex)[:64]
    if any(m.get("msg_id") == msg_id and m["direction"] == "in" and m["peer"] == sender
           for m in st["messages"].values()):
        return None     # the same message twice
    st["messages"][row_id] = {"id": row_id, "msg_id": msg_id, "thread": str(msg.get("thread") or uuid.uuid4().hex)[:32],
                              "direction": "in", "peer": sender, "recipients": msg.get("recipients") or [my_address],
                              "kind": kind, "subject": str(msg.get("subject") or "")[:MAX_SUBJECT],
                              "text": str(msg.get("text") or "")[:MAX_TEXT], "status": status_v,
                              "verified": status_v == "new", "problem": problem, "in_reply_to": msg.get("in_reply_to"),
                              "created_at": time.time(), "read": False}
    save_store(st)
    return {"id": row_id, "peer": sender, "subject": msg.get("subject") or "", "text": msg.get("text") or "",
            "status": status_v, "trust": trust, "kind": kind}


def check() -> Dict[str, Any]:
    """Picks up new mail from the relay, opens and verifies it, stores it, then deletes it there."""
    cfg, ident = config(), identity()
    if not (cfg.get("address") and ident):
        return {"success": False, "error": "No address claimed yet. Run claim first."}
    base = relay_base(cfg["domain"])
    try:
        r = _http("GET", f"{base}/v1/mail", headers=mc.signed_headers(ident, cfg["name"], "GET", "/v1/mail"))
        if r.status_code != 200:
            raise MailError(_detail(r))
    except (httpx.HTTPError, MailError) as e:
        cfg.update(last_error=f"Couldn't check mail: {e}", last_check=time.time())
        save_config(cfg)
        return {"success": False, "error": cfg["last_error"]}
    got, done = [], []
    for item in r.json().get("messages", []):
        try:
            stored = _receive(ident, cfg["address"], item["envelope"])
            if stored:
                got.append(stored)
        except Exception:
            pass        # a bad envelope is dropped, never trusted
        done.append(item["id"])
    if done:
        _http("POST", f"{base}/v1/mail/ack", json={"ids": done},
              headers=mc.signed_headers(ident, cfg["name"], "POST", "/v1/mail/ack"))
    cfg.update(last_check=time.time(), last_error=None)
    save_config(cfg)
    return {"success": True, "new": len(got),
            "messages": [{"id": m["id"], "peer": m["peer"], "subject": m["subject"],
                          "status": m["status"], "trust": m["trust"], "kind": m["kind"]} for m in got]}


# ---------------------------------------------------------------- reading

def list_messages(box: str = "inbox") -> List[Dict[str, Any]]:
    """box: inbox (contacts), requests (unknown senders), sent, held."""
    st = store()
    msgs = list(st["messages"].values())
    if box == "sent":
        out = [m for m in msgs if m["direction"] == "out" and m["status"] != "discarded"]
    elif box == "held":
        out = [m for m in msgs if m["status"] == "held"]
    else:
        want_unknown = box == "requests"
        out = [m for m in msgs if m["direction"] == "in" and m["status"] == "new"
               and (st["contacts"].get(m["peer"], {}).get("trust", "unknown") == "unknown") == want_unknown]
    return sorted(out, key=lambda m: m["created_at"], reverse=True)[:200]


def get_message(mid: str, mark_read: bool = True) -> Optional[Dict[str, Any]]:
    st = store()
    m = st["messages"].get(mid)
    if not m:
        return None
    if mark_read and m["direction"] == "in":
        m["read"] = True
        save_store(st)
    return m


def threads(box: str = "inbox") -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for m in list_messages(box):
        t = grouped.setdefault(m["thread"], {"thread": m["thread"], "count": 0, "unread": 0, "peers": set()})
        t["count"] += 1
        if m["direction"] == "in" and not m.get("read"):
            t["unread"] += 1
        t["peers"].add(m["peer"])
        if t.get("last_at", 0) < m["created_at"]:
            t.update(last_at=m["created_at"], last={"id": m["id"], "peer": m["peer"], "subject": m["subject"],
                                                   "text": m["text"][:200], "direction": m["direction"]})
    out = sorted(grouped.values(), key=lambda t: t["last_at"], reverse=True)
    for t in out:
        t["peers"] = sorted(t["peers"])
    return out


# ---------------------------------------------------------------- self-host directory: register + heartbeat

def _endpoint_ok(endpoint: str) -> bool:
    m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?(/.*)?$", endpoint or "", re.I)
    if not m:
        return False
    if m.group(1).lower() == "https":
        return True
    host = m.group(2).lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local") or host.endswith(".localhost")


def register_selfhost(endpoint: str) -> Dict[str, Any]:
    """Registers a self-hosted endpoint for my address on the relay's directory.

    This is the v1 directory extension: the relay keeps address -> (endpoint URL, pubkey)
    so other agents can find where to reach this agent directly. Registration is signed,
    and the relay's challenge is answered automatically, so only the address owner can
    set or change it. Needs a relay that serves /v1/directory/*; others answer 404.
    """
    cfg, ident = config(), identity()
    if not (cfg.get("address") and ident):
        return {"success": False, "error": "No address claimed yet. Run claim first."}
    endpoint = (endpoint or "").strip().rstrip("/")
    if not _endpoint_ok(endpoint):
        return {"success": False, "error": "The endpoint must be an https:// URL (http:// is for local hosts only)."}
    base = relay_base(cfg["domain"])
    try:
        r = _http("POST", f"{base}/v1/directory/register",
                  json=mc.directory_registration(ident, cfg["address"], endpoint))
    except httpx.HTTPError as e:
        return {"success": False, "error": f"Couldn't reach {cfg['domain']}: {type(e).__name__}"}
    if r.status_code == 404:
        return {"success": False, "error": "This relay doesn't serve a self-host directory yet."}
    if r.status_code != 200:
        return {"success": False, "error": _detail(r)}
    d = r.json()
    if d.get("status") == "challenge":
        # prove the key is live by signing the relay's challenge
        try:
            r2 = _http("POST", f"{base}/v1/directory/challenge",
                       json=mc.directory_challenge_answer(ident, d["challenge_id"], d["challenge"], cfg["address"]))
        except httpx.HTTPError as e:
            return {"success": False, "error": f"Couldn't answer the relay's challenge: {type(e).__name__}"}
        if r2.status_code != 200:
            return {"success": False, "error": _detail(r2)}
        d = r2.json()
    if not d.get("registered"):
        return {"success": False, "error": d.get("detail") or "Registration didn't complete."}
    cfg.update(endpoint=endpoint, selfhost_registered_at=time.time())
    save_config(cfg)
    return {"success": True, "address": cfg["address"], "endpoint": d.get("endpoint") or endpoint}


def heartbeat() -> Dict[str, Any]:
    """Tells the relay this address is alive and its self-hosted endpoint is current.

    The relay serves records as stale after 15 minutes without a heartbeat, so run
    this about every 5 minutes while the endpoint is up.
    """
    cfg, ident = config(), identity()
    if not (cfg.get("address") and ident):
        return {"success": False, "error": "No address claimed yet. Run claim first."}
    try:
        r = _http("POST", f"{relay_base(cfg['domain'])}/v1/directory/heartbeat",
                  json=mc.directory_heartbeat_sig(ident, cfg["address"]))
    except httpx.HTTPError as e:
        return {"success": False, "error": f"Couldn't reach {cfg['domain']}: {type(e).__name__}"}
    if r.status_code == 404:
        return {"success": False, "error": "This relay doesn't serve a self-host directory yet."}
    if r.status_code != 200:
        return {"success": False, "error": _detail(r)}
    d = r.json()
    cfg.update(last_heartbeat=time.time())
    save_config(cfg)
    return {"success": True, "address": d.get("address") or cfg["address"], "last_seen": d.get("last_seen")}


def selfhost_lookup(address: str) -> Dict[str, Any]:
    """Looks up another address's self-hosted endpoint in the relay directory."""
    name, domain = parse_address(address)
    try:
        r = _http("GET", f"{relay_base(domain)}/v1/directory/{address.strip().lower()}")
    except httpx.HTTPError as e:
        raise MailError(f"Couldn't reach {domain} ({type(e).__name__}).")
    if r.status_code == 404:
        raise MailError(f"{address} has no live self-hosted endpoint registered.")
    if r.status_code != 200:
        raise MailError(_detail(r))
    return r.json()
