"""Crypto tests: fixed interop vectors plus a live seal/open round trip.

The fixed vectors below pin the exact byte-level conventions of the protocol so a
TypeScript (or any other) rewrite can prove wire compatibility:

- base64url WITHOUT padding for all keys, signatures, envelope parts
- canonical JSON: json.dumps with sort_keys=True, separators=(",", ":"), ensure_ascii=False, UTF-8
- HKDF-SHA256: salt = one-time public key || recipient public key, info = b"xod-mail-v1"
- associated data = the recipient address, lowercased, UTF-8
- Ed25519 signatures over:
    message signing:     canonical({"msg": inner, "sig": ..., "keys": ...}) is signed over canonical(inner)
    registration:        b"xod-register|{name}|{sign_pub}|{box_pub}|{ts}"
    relay request auth:  b"xod-relay|{METHOD}|{path}|{name}|{ts}"
    directory register:  b"xod-dir-register|{address}|{endpoint}|{sign_pub}|{box_pub}|{ts}"
    directory challenge: b"xod-dir-challenge|{challenge_id}|{challenge}|{address}"
    directory heartbeat: b"xod-dir-heartbeat|{address}|{ts}"
- safety number: sha256(raw_sign_pub || raw_box_pub), first 15 bytes as big int,
  zero-padded to 36 digits, last 30 digits grouped in sixes of five.

The fixed test key pairs below are arbitrary, non-secret test material generated for
this suite. They carry no real identity and must never be used for anything else.
"""
import json

import pytest

from agentmail_client import mail_crypto as mc

# --- fixed test material (see module docstring) --------------------------------
SIGN_PRIV_B64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
BOX_PRIV_B64 = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A"
SIGN_PUB = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
BOX_PUB = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns"
FIXED_MSG = {"from": "alice@post.example.com", "to": "bob@post.example.com", "id": "m1",
             "thread": "t1", "kind": "message", "subject": "Hi", "text": "Hello, Bob.", "v": 1}
FIXED_CANON = b'{"from":"alice@post.example.com","id":"m1","kind":"message","subject":"Hi","text":"Hello, Bob.","thread":"t1","to":"bob@post.example.com","v":1}'
FIXED_SIG = "FMrvN12cRq6C9JvK-x1lPuX2CuqTAhlnnjgGgRsJa7TdBL1-cWV2-XY5pLIEhSLNY8axrbnEh0uOwKxPgQNjCg"
FIXED_SAFETY = "34536 57695 19044 19860 85820 36632"
FIXED_TS = 1700000000
FIXED_REG_SIG = "zCBAN2Ltes2JRc08uMDDMXjOM0Mt0i8E49jOF6-qChgjxgIY0ZFUfZ3leEibG18g7Pdwq-PTl-6PAJp64oxTDA"
FIXED_HDR_SIG = "bt7tTD00aKl4QzdVUFLeED6lbAF14tRzAWAn0HqHEIAWwUDFHIQYWO3AC1FZrex-xCyGj7sTvNMFSoN7zz4LAw"
FIXED_DIR_ADDR = "alice@post.example.com"
FIXED_DIR_ENDPOINT = "https://alice.example.com/agent"
FIXED_DIR_REG_SIG = "9g_XqRGN5tjGITNMhQ4LvvM2FV5ovKHbVEa8RoPrqHx61QQ-6uc8kJ2YUlvBSrZL2Hb2-TKonfaLf8CcI99aDA"
FIXED_DIR_CHA_SIG = "VpuHlGZcs3n0ZpjAYe8gsA3GaDAT8xxcUWTyuhmG69xdD6-W9jD7glj50K-XvCQAUdZHqSFD4KYOaKG8IVIkCw"
FIXED_DIR_HB_SIG = "cl-NOCefrwfFCL4QFZCDGIUnFMMlCrJh8OCbfTCDrLHs_tBPeeMIk5BL7YwQ6xJ97HtWVKPCtqH1uzJ5n0EIBQ"


@pytest.fixture()
def fixed_identity():
    return mc.Identity.from_secrets(SIGN_PRIV_B64, BOX_PRIV_B64)


def test_canonical_json_exact_bytes():
    assert mc.canonical(FIXED_MSG) == FIXED_CANON


def test_canonical_json_conventions():
    # sorted keys, no spaces, unicode kept as-is (not \u escaped)
    assert mc.canonical({"b": 1, "a": [1, 2], "z": "caf\u00e9"}) == '{"a":[1,2],"b":1,"z":"caf\u00e9"}'.encode()


def test_base64url_no_padding():
    assert "=" not in SIGN_PUB and "=" not in FIXED_SIG
    assert mc.b64d(SIGN_PUB) != b"" and len(mc.b64d(SIGN_PUB)) == 32


def test_identity_round_trip_from_secrets(fixed_identity):
    assert fixed_identity.sign_pub == SIGN_PUB
    assert fixed_identity.box_pub == BOX_PUB
    s, b = fixed_identity.secrets()
    again = mc.Identity.from_secrets(s, b)
    assert again.sign_pub == SIGN_PUB and again.box_pub == BOX_PUB


def test_fixed_message_signature_matches_vector(fixed_identity):
    assert mc.canonical(FIXED_MSG) == FIXED_CANON
    assert fixed_identity.sign(FIXED_CANON) == FIXED_SIG
    assert mc.verify(SIGN_PUB, FIXED_CANON, FIXED_SIG)


def test_fixed_registration_signature_matches_vector(fixed_identity):
    reg = mc.registration(fixed_identity, "alice", ts=FIXED_TS)
    assert reg["sig"] == FIXED_REG_SIG
    assert mc.verify(SIGN_PUB, f"xod-register|alice|{SIGN_PUB}|{BOX_PUB}|{FIXED_TS}".encode(), FIXED_REG_SIG)


def test_fixed_relay_header_signature_matches_vector(fixed_identity):
    h = mc.signed_headers(fixed_identity, "alice", "GET", "/v1/mail", ts=FIXED_TS)
    assert h["X-Xod-Sig"] == FIXED_HDR_SIG
    assert h["X-Xod-Name"] == "alice" and h["X-Xod-Time"] == str(FIXED_TS)


def test_fixed_safety_number_matches_vector():
    assert mc.safety_number(SIGN_PUB, BOX_PUB) == FIXED_SAFETY


def test_fixed_directory_signatures_match_vectors(fixed_identity):
    reg = mc.directory_registration(fixed_identity, FIXED_DIR_ADDR, FIXED_DIR_ENDPOINT, ts=FIXED_TS)
    assert reg["sig"] == FIXED_DIR_REG_SIG
    assert mc.verify(SIGN_PUB,
                     f"xod-dir-register|{FIXED_DIR_ADDR}|{FIXED_DIR_ENDPOINT}|{SIGN_PUB}|{BOX_PUB}|{FIXED_TS}".encode(),
                     FIXED_DIR_REG_SIG)
    ans = mc.directory_challenge_answer(fixed_identity, "cid123", "chal456", FIXED_DIR_ADDR)
    assert ans["sig"] == FIXED_DIR_CHA_SIG
    hb = mc.directory_heartbeat_sig(fixed_identity, FIXED_DIR_ADDR, ts=FIXED_TS)
    assert hb["sig"] == FIXED_DIR_HB_SIG


def test_verify_rejects_wrong_key():
    assert not mc.verify(SIGN_PUB, FIXED_CANON, FIXED_SIG[:-2] + "AA")


def test_seal_open_round_trip():
    alice = mc.Identity.new()
    bob = mc.Identity.new()
    env = mc.seal(alice, "alice@post.example.com", "bob@post.example.com", bob.box_pub,
                  {"id": "m1", "thread": "t1", "kind": "message", "subject": "Hi", "text": "hello"})
    assert set(env) == {"v", "eph", "nonce", "ct"}
    opened = mc.open_envelope(bob, "bob@post.example.com", env)
    assert opened["signature_ok"]
    assert opened["msg"]["text"] == "hello"
    assert opened["msg"]["from"] == "alice@post.example.com"
    assert opened["keys"]["sign"] == alice.sign_pub


def test_seal_is_randomized_per_send():
    alice, bob = mc.Identity.new(), mc.Identity.new()
    m = {"id": "m1", "thread": "t1", "kind": "message", "text": "same"}
    e1 = mc.seal(alice, "a@x", "b@x", bob.box_pub, m)
    e2 = mc.seal(alice, "a@x", "b@x", bob.box_pub, m)
    assert e1["ct"] != e2["ct"] and e1["nonce"] != e2["nonce"]


def test_open_rejects_wrong_recipient():
    alice, bob, carol = mc.Identity.new(), mc.Identity.new(), mc.Identity.new()
    env = mc.seal(alice, "a@x", "b@x", bob.box_pub, {"text": "hi"})
    with pytest.raises(ValueError):
        mc.open_envelope(carol, "c@x", env)


def test_open_rejects_envelope_meant_for_someone_else():
    # AAD is the recipient address: opening as anyone else fails decryption,
    # so a forwarded envelope can never be mistaken for mine.
    alice, bob = mc.Identity.new(), mc.Identity.new()
    env = mc.seal(alice, "a@x", "b@x", bob.box_pub, {"text": "hi"})
    with pytest.raises(ValueError):
        mc.open_envelope(bob, "someone-else@x", env)


def test_open_rejects_garbage():
    bob = mc.Identity.new()
    with pytest.raises(ValueError):
        mc.open_envelope(bob, "b@x", {"v": 1, "eph": "AA", "nonce": "AA", "ct": "AA"})
