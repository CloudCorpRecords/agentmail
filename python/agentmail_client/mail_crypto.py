"""
Agent Mail cryptography: who you are, and sealed envelopes only the recipient can open.

Identity: an Ed25519 signing key (proves who wrote a message) and an X25519 key (lets others
seal messages to you). In this package the private keys live in a local key file
(AGENTMAIL_HOME/keys.json, mode 0600), not in an OS keychain.

Sealing a message to someone:
  1. the message (from, to, text, ids...) is signed with the sender's Ed25519 key;
  2. a one-time X25519 key is made; ECDH with the recipient's X25519 key, then HKDF-SHA256,
     gives a fresh key for ChaCha20-Poly1305;
  3. the signed message is encrypted with the recipient's address as associated data.
The envelope holds only the one-time public key, a nonce and ciphertext. The relay can't read it
and can't tell who sent it; the recipient opens it and checks the signature against the key it
has pinned for that sender.

Interop note: every byte-level convention in this file (canonical JSON, base64url without
padding, HKDF salt = one-time public key || recipient public key, info = b"xod-mail-v1",
address lowercased as associated data, signature input strings) is pinned by the fixed test
vectors in tests/test_crypto.py. A rewrite in another language must reproduce those exact
vectors to stay wire-compatible.
"""
import base64
import hashlib
import json
import os
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 1
INFO = b"xod-mail-v1"
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Identity:
    def __init__(self, sign: Ed25519PrivateKey, box: X25519PrivateKey):
        self.sign_key, self.box_key = sign, box

    @classmethod
    def new(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def from_secrets(cls, sign_b64: str, box_b64: str) -> "Identity":
        return cls(Ed25519PrivateKey.from_private_bytes(b64d(sign_b64)), X25519PrivateKey.from_private_bytes(b64d(box_b64)))

    def secrets(self) -> Tuple[str, str]:
        priv = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return b64e(self.sign_key.private_bytes(*priv)), b64e(self.box_key.private_bytes(*priv))

    @property
    def sign_pub(self) -> str:
        return b64e(self.sign_key.public_key().public_bytes(*RAW))

    @property
    def box_pub(self) -> str:
        return b64e(self.box_key.public_key().public_bytes(*RAW))

    def sign(self, data: bytes) -> str:
        return b64e(self.sign_key.sign(data))


def verify(sign_pub: str, data: bytes, sig: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64d(sign_pub)).verify(b64d(sig), data)
        return True
    except Exception:
        return False


def safety_number(sign_pub: str, box_pub: str) -> str:
    """A short code two people can compare (in person or on a call) to be sure the keys are right."""
    digest = hashlib.sha256(b64d(sign_pub) + b64d(box_pub)).digest()
    n = int.from_bytes(digest[:15], "big")
    digits = str(n).zfill(36)[-30:]
    return " ".join(digits[i:i + 5] for i in range(0, 30, 5))


def _key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub, info=INFO).derive(shared)


def seal(sender: Identity, sender_address: str, recipient_address: str, recipient_box_pub: str,
         message: Dict[str, Any]) -> Dict[str, str]:
    """Signs and encrypts a message for one recipient. Returns the envelope to post to the relay."""
    inner = {**message, "v": VERSION, "from": sender_address, "to": recipient_address}
    payload = canonical({"msg": inner, "sig": sender.sign(canonical(inner)),
                         "keys": {"sign": sender.sign_pub, "box": sender.box_pub}})
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(*RAW)
    rpub = b64d(recipient_box_pub)
    key = _key(eph.exchange(X25519PublicKey.from_public_bytes(rpub)), eph_pub, rpub)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, payload, recipient_address.lower().encode())
    return {"v": VERSION, "eph": b64e(eph_pub), "nonce": b64e(nonce), "ct": b64e(ct)}


def open_envelope(me: Identity, my_address: str, envelope: Dict[str, str]) -> Dict[str, Any]:
    """Decrypts an envelope addressed to me. Returns {"msg", "sig", "keys", "signature_ok"}.
    Raises ValueError if it can't be opened. The caller still has to check that keys["sign"]
    is the key it trusts for msg["from"]."""
    try:
        eph_pub = b64d(envelope["eph"])
        my_pub = b64d(me.box_pub)
        key = _key(me.box_key.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, my_pub)
        payload = ChaCha20Poly1305(key).decrypt(b64d(envelope["nonce"]), b64d(envelope["ct"]), my_address.lower().encode())
        data = json.loads(payload)
    except Exception as e:
        raise ValueError(f"couldn't open the envelope: {type(e).__name__}")
    msg, sig, keys = data.get("msg") or {}, data.get("sig") or "", data.get("keys") or {}
    ok = bool(keys.get("sign")) and verify(keys["sign"], canonical(msg), sig)
    if (msg.get("to") or "").lower() != my_address.lower():
        ok = False      # sealed for someone else and forwarded: don't trust it
    return {"msg": msg, "sig": sig, "keys": keys, "signature_ok": ok}


# ---------------------------------------------------------------- relay request signing

def signed_headers(me: Identity, name: str, method: str, path: str, ts: Optional[int] = None) -> Dict[str, str]:
    import time
    ts = ts or int(time.time())
    return {"X-Xod-Name": name, "X-Xod-Time": str(ts),
            "X-Xod-Sig": me.sign(f"xod-relay|{method.upper()}|{path}|{name}|{ts}".encode())}


def registration(me: Identity, name: str, ts: Optional[int] = None) -> Dict[str, Any]:
    import time
    ts = ts or int(time.time())
    return {"name": name, "sign_pub": me.sign_pub, "box_pub": me.box_pub, "ts": ts,
            "sig": me.sign(f"xod-register|{name}|{me.sign_pub}|{me.box_pub}|{ts}".encode())}


# ---------------------------------------------------------------- self-host directory signing

def directory_registration(me: Identity, address: str, endpoint: str, ts: Optional[int] = None) -> Dict[str, Any]:
    """Registration for the relay's self-host directory (address -> endpoint URL + pubkey).

    This is the v1 directory extension. The relay answers with a challenge the owner must
    sign (see directory_challenge_answer), so records can't be forged or replayed.
    """
    import time
    ts = ts or int(time.time())
    endpoint = endpoint.rstrip("/")
    return {"address": address, "endpoint": endpoint, "sign_pub": me.sign_pub, "box_pub": me.box_pub, "ts": ts,
            "sig": me.sign(f"xod-dir-register|{address}|{endpoint}|{me.sign_pub}|{me.box_pub}|{ts}".encode())}


def directory_challenge_answer(me: Identity, challenge_id: str, challenge: str, address: str) -> Dict[str, Any]:
    """Answers the relay's directory challenge, proving the registering key is live."""
    return {"challenge_id": challenge_id, "address": address,
            "sig": me.sign(f"xod-dir-challenge|{challenge_id}|{challenge}|{address}".encode())}


def directory_heartbeat_sig(me: Identity, address: str, ts: Optional[int] = None) -> Dict[str, Any]:
    """Liveness ping for a live directory record."""
    import time
    ts = ts or int(time.time())
    return {"address": address, "ts": ts,
            "sig": me.sign(f"xod-dir-heartbeat|{address}|{ts}".encode())}
