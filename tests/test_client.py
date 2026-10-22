"""Client tests against the in-process fake relay.

Two agents (alice, bob) claim addresses on the fake relay and trade real sealed
mail through the real HTTP protocol. Nothing is mocked inside the client:
envelopes are sealed, posted, fetched, opened and acked for real.
"""
import json
import os
import subprocess
import sys

import pytest

from agentmail_client import client, mail_crypto as mc
from agentmail_client.client import MailError


def claim_agent(home_dir, relay_domain, name, monkeypatch):
    """Claim an address in a separate AGENTMAIL_HOME (a second agent on the same machine)."""
    monkeypatch.setenv("AGENTMAIL_HOME", str(home_dir))
    res = client.claim(name, relay=relay_domain)
    assert res["success"], res
    return res


def test_claim_writes_keys_with_strict_perms(home, relay, monkeypatch):
    res = client.claim("alice", relay=relay.domain)
    assert res["success"] and res["address"] == f"alice@{relay.domain}"
    assert res["safety_number"]
    keys = home / "keys.json"
    assert keys.exists()
    assert oct(os.stat(keys).st_mode)[-3:] == "600"
    cfg = json.loads((home / "config.json").read_text())
    assert cfg["address"] == f"alice@{relay.domain}"


def test_claim_fails_with_taken_name(home, relay, tmp_path, monkeypatch):
    assert client.claim("alice", relay=relay.domain)["success"]
    other = tmp_path / "other"
    monkeypatch.setenv("AGENTMAIL_HOME", str(other))
    res = client.claim("alice", relay=relay.domain)
    assert not res["success"] and "taken" in res["error"]


def test_send_and_receive_round_trip(home, relay, tmp_path, monkeypatch):
    claim_agent(home, relay.domain, "alice", monkeypatch)
    claim_agent(tmp_path / "bob", relay.domain, "bob", monkeypatch)

    # alice sends (as alice)
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    sent = client.send(f"bob@{relay.domain}", "Hello, Bob.", subject="Hi")
    assert sent["success"] and sent["sent_to"] == [f"bob@{relay.domain}"]

    # bob checks (as bob): decrypts, verifies, stores, acks
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "bob"))
    got = client.check()
    assert got["success"] and got["new"] == 1
    m = got["messages"][0]
    assert m["peer"] == f"alice@{relay.domain}" and m["status"] == "new" and m["trust"] == "unknown"

    stored = client.get_message(m["id"])
    assert stored["text"] == "Hello, Bob." and stored["verified"] and stored["subject"] == "Hi"
    assert stored["read"]        # get_message marks read

    # the relay deleted the envelope on ack
    assert relay.mail.get("bob") == []

    # a second check finds nothing new
    assert client.check()["new"] == 0


def test_stranger_goes_to_requests_until_trusted(home, relay, tmp_path, monkeypatch):
    claim_agent(home, relay.domain, "alice", monkeypatch)
    claim_agent(tmp_path / "bob", relay.domain, "bob", monkeypatch)
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    client.send(f"bob@{relay.domain}", "hi from a stranger")
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "bob"))
    client.check()
    assert client.list_messages("inbox") == []
    assert len(client.list_messages("requests")) == 1
    assert client.set_trust(f"alice@{relay.domain}", "known")
    assert len(client.list_messages("inbox")) == 1


def test_changed_keys_raise_on_resolve(home, relay, tmp_path, monkeypatch):
    claim_agent(home, relay.domain, "alice", monkeypatch)
    claim_agent(tmp_path / "bob", relay.domain, "bob", monkeypatch)
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    client.send(f"bob@{relay.domain}", "first contact")     # pins bob's keys
    # bob rotates his encryption key (same signing key, same owner: the relay allows it)
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "bob"))
    old = json.loads((tmp_path / "bob" / "keys.json").read_text())
    ident = mc.Identity.from_secrets(old["sign"], old["box"])
    rotated = mc.Identity(ident.sign_key, mc.Identity.new().box_key)
    s, b = rotated.secrets()
    (tmp_path / "bob" / "keys.json").write_text(json.dumps({"sign": s, "box": b}))
    res = client.claim("bob", relay=relay.domain)
    assert res["success"]
    # alice now refuses to seal to the changed keys until the safety number is checked
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    with pytest.raises(MailError, match="keys have changed"):
        client.resolve(f"bob@{relay.domain}")


def test_lookup_of_missing_address_raises(home, relay):
    with pytest.raises(MailError, match="no"):
        client.lookup(f"nobody@{relay.domain}")


def test_selfhost_register_heartbeat_lookup(home, relay):
    res = client.claim("alice", relay=relay.domain)
    assert res["success"]
    # registration answers the relay's challenge automatically
    reg = client.register_selfhost("https://alice.example.com/agent")
    assert reg["success"] and reg["endpoint"] == "https://alice.example.com/agent"
    assert relay.directory[f"alice@{relay.domain}"]["status"] == "live"
    hb = client.heartbeat()
    assert hb["success"] and hb["address"] == f"alice@{relay.domain}" and hb["last_seen"]
    found = client.selfhost_lookup(f"alice@{relay.domain}")
    assert found["endpoint"] == "https://alice.example.com/agent"
    assert found["sign_pub"] and found["box_pub"]
    with pytest.raises(MailError, match="no live"):
        client.selfhost_lookup(f"bob@{relay.domain}")


def test_selfhost_register_rejects_bad_url(home, relay):
    assert client.claim("alice", relay=relay.domain)["success"]
    assert not client.register_selfhost("not-a-url")["success"]
    # plain http is only allowed for local hosts, like the real relay
    assert not client.register_selfhost("http://alice.example.com/agent")["success"]
    ok = client.register_selfhost("http://127.0.0.1:9999/agent")
    assert ok["success"]


def test_send_requires_claim(home, relay):
    with pytest.raises(MailError, match="claim"):
        client.send(f"bob@{relay.domain}", "no identity here")


def test_cli_status_and_version(home):
    r = subprocess.run([sys.executable, "-m", "agentmail_client", "status"],
                       capture_output=True, text=True, cwd="python",
                       env={**os.environ, "AGENTMAIL_HOME": str(home)})
    assert r.returncode == 0
    assert json.loads(r.stdout)["set_up"] is False
    r = subprocess.run([sys.executable, "-m", "agentmail_client", "--version"],
                       capture_output=True, text=True, cwd="python",
                       env={**os.environ, "AGENTMAIL_HOME": str(home)})
    assert r.returncode == 0 and "0.1.0" in r.stdout


def test_mcp_tools_list_and_claim(home, relay, monkeypatch):
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    from agentmail_client import mcp_server
    listed = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = [t["name"] for t in listed["result"]["tools"]]
    assert names == ["claim_address", "lookup", "send_message", "check_inbox",
                     "read_message", "register_selfhost", "heartbeat"]
    called = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                "params": {"name": "claim_address",
                                           "arguments": {"name": "mcpagent", "relay": relay.domain}}})
    payload = json.loads(called["result"]["content"][0]["text"])
    assert payload["success"] and payload["address"] == f"mcpagent@{relay.domain}"


def test_mcp_send_and_check_end_to_end(home, relay, tmp_path, monkeypatch):
    from agentmail_client import mcp_server
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "claim_address", "arguments": {"name": "one", "relay": relay.domain}}})
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "two"))
    mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "claim_address", "arguments": {"name": "two", "relay": relay.domain}}})
    monkeypatch.setenv("AGENTMAIL_HOME", str(home))
    sent = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                              "params": {"name": "send_message",
                                         "arguments": {"to": f"two@{relay.domain}", "text": "mcp hello"}}})
    assert json.loads(sent["result"]["content"][0]["text"])["success"]
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "two"))
    got = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": "check_inbox", "arguments": {}}})
    payload = json.loads(got["result"]["content"][0]["text"])
    assert payload["success"] and payload["new"] == 1
    read = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                              "params": {"name": "read_message",
                                         "arguments": {"id": payload["messages"][0]["id"]}}})
    assert json.loads(read["result"]["content"][0]["text"])["text"] == "mcp hello"


def test_inboxwatch_env_names_win(tmp_path, monkeypatch):
    """The rename: INBOXWATCH_* is primary, AGENTMAIL_* is a legacy alias."""
    from pathlib import Path

    from agentmail_client import client as c
    new_home = tmp_path / "newhome"
    monkeypatch.setenv("INBOXWATCH_HOME", str(new_home))
    monkeypatch.setenv("AGENTMAIL_HOME", str(tmp_path / "oldhome"))
    assert c.home() == new_home
    monkeypatch.delenv("INBOXWATCH_HOME")
    assert c.home() == Path(str(tmp_path / "oldhome"))
    monkeypatch.setenv("INBOXWATCH_RELAY", "Relay.Example.com")
    monkeypatch.setenv("AGENTMAIL_RELAY", "old.example.com")
    assert c.default_relay() == "relay.example.com"
    monkeypatch.delenv("INBOXWATCH_RELAY")
    assert c.default_relay() == "old.example.com"
