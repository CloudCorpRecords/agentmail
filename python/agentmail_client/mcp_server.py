"""InboxWatch MCP server over stdio (Agent Mail protocol). No third-party dependencies, stdlib only.

Speaks JSON-RPC with Content-Length framing (MCP stdio transport). Tools map
directly onto the client ops; each returns a JSON text payload with explicit
fields, never placeholders. The calling agent decides its own reply/send policy:
the server just operates the mailbox.
"""
import json
import sys
import traceback

from . import __version__, client
from .client import MailError

SERVER_NAME = "inboxwatch"
PROTOCOL_VERSION = "2024-11-05"


def tool(name, description, schema, handler):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": schema,
                            "required": [k for k, v in schema.items() if v.get("required")],
                            "additionalProperties": False}, "handler": handler}


def _req(**kw):
    return kw


TOOLS = [
    tool("claim_address",
         "Claim an agent address (name@relay) on the relay with this machine's keys, made now if needed. "
         "Returns the address and the safety number to compare with contacts.",
         {"name": {"type": "string", "description": "name to claim, e.g. sam", "required": True},
          "relay": {"type": "string", "description": "relay domain; default is the INBOXWATCH_RELAY env var"}},
         lambda a: client.claim(a["name"], relay=a.get("relay"))),
    tool("lookup",
         "Look up an agent address's public keys on its relay directory.",
         {"address": {"type": "string", "description": "agent address, e.g. sam@post.example.com", "required": True}},
         lambda a: client.lookup(a["address"])),
    tool("send_message",
         "Seal and send an E2E encrypted message to one or more agent addresses now. "
         "Recipients' keys are pinned on first use. Returns per-recipient results.",
         {"to": {"type": "string", "description": "recipient address, or comma separated list", "required": True},
          "text": {"type": "string", "description": "message text", "required": True},
          "subject": {"type": "string", "description": "subject line"},
          "kind": {"type": "string", "description": "message, task_request or reply", "enum": ["message", "task_request", "reply"]},
          "thread": {"type": "string", "description": "thread id to continue"}},
         lambda a: client.send(a["to"], a["text"], subject=a.get("subject", ""),
                               kind=a.get("kind", "message"), thread=a.get("thread"))),
    tool("check_inbox",
         "Pick up new mail from the relay: opens each envelope, verifies signatures, "
         "stores verified mail and holds suspicious mail. Deletes picked-up envelopes from the relay. "
         "Returns the new messages (subject, sender, status, trust).",
         {},
         lambda a: client.check()),
    tool("read_message",
         "Read one stored message by id (marks it read).",
         {"id": {"type": "string", "description": "message id from check_inbox or inbox listing", "required": True}},
         lambda a: client.get_message(a["id"]) or {"success": False, "error": f"No message {a['id']}."}),
    tool("register_selfhost",
         "Register a self-hosted endpoint for this address on the relay directory "
         "(address -> endpoint URL + pubkey), signed by the address owner.",
         {"endpoint": {"type": "string", "description": "public http(s) URL of your endpoint", "required": True}},
         lambda a: client.register_selfhost(a["endpoint"])),
    tool("heartbeat",
         "Tell the relay this address is alive and its self-hosted endpoint is current.",
         {},
         lambda a: client.heartbeat()),
]

TOOL_MAP = {t["name"]: t for t in TOOLS}


def _read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline().decode("latin-1")
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0"))
    if not length:
        return None
    return json.loads(sys.stdin.buffer.read(length).decode("utf-8"))


def _send(obj):
    body = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("latin-1"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def _log(msg):
    sys.stderr.write(f"[inboxwatch-mcp] {msg}\n")
    sys.stderr.flush()


def _result_text(obj):
    return {"content": [{"type": "text", "text": json.dumps(obj, indent=2, sort_keys=True)}]}


def handle(req):
    method, rid, params = req.get("method"), req.get("id"), req.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"protocolVersion": PROTOCOL_VERSION,
                           "capabilities": {"tools": {}},
                           "serverInfo": {"name": SERVER_NAME, "version": __version__}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"tools": [{k: t[k] for k in ("name", "description", "inputSchema")} for t in TOOLS]}}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        t = TOOL_MAP.get(name)
        if not t:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": f"unknown tool: {name}"}}
        try:
            return {"jsonrpc": "2.0", "id": rid, "result": _result_text(t["handler"](args))}
        except MailError as e:
            return {"jsonrpc": "2.0", "id": rid, "result": _result_text({"success": False, "error": str(e)})}
        except Exception as e:
            _log(f"tool {name} crashed: {traceback.format_exc(limit=3)}")
            return {"jsonrpc": "2.0", "id": rid,
                    "result": _result_text({"success": False, "error": f"tool failed: {type(e).__name__}"})}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"unknown method: {method}"}}


def main():
    _log(f"starting {SERVER_NAME} v{__version__}")
    while True:
        try:
            req = _read_message()
        except Exception as e:
            _log(f"read error: {e}")
            break
        if req is None:
            break
        if req.get("method", "").startswith("notifications/"):
            continue      # notifications get no response
        try:
            _send(handle(req))
        except Exception as e:
            _log(f"write error: {e}")
            break


if __name__ == "__main__":
    main()
