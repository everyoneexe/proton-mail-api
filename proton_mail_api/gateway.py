"""
Proton Mail Gateway — read-only multi-account mail reader (HTTP).

Deliberately a *reader*: it lists and decrypts mail. It exposes no verification
code extraction and no mutations (address create/enable/disable/delete, token
refresh). Those stay in the Python API and CLI, where the caller is the account
owner rather than any client that can reach a TCP port.

Why no /code endpoint: a one-shot "give me the verification code for this
address" URL is an account-takeover primitive. Anyone who reaches the port can
harvest the codes for every address on every configured account, and the answer
is only as correct as a regex guess. Callers that genuinely need it use
ProtonMailClient.wait_code() in their own process.

Authentication: every endpoint except / requires a bearer token
(Authorization: Bearer <token>, or ?token=<token>). The token comes from
--token or the PROTON_GATEWAY_TOKEN environment variable. Binds 127.0.0.1 by
default.

Endpoints:
  GET /                      → service info (no auth, no account data)
  GET /accounts              → configured account aliases + emails
  GET /messages              → list messages (account, page, size, unread, q)
  GET /messages/<msg_id>     → read one message + PGP decrypt
  GET /addresses             → addresses of one account, or all with all=1

Start:
  python -m proton_mail_api.gateway --configs a.json,b.json --token "$TOKEN"
"""
import argparse
import hmac
import logging
import os
import re
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

import httpx
from flask import Flask, jsonify, request

from .reader import ProtonReader

log = logging.getLogger(__name__)

app = Flask(__name__)

# Multi-account: {"alias": ProtonReader}
readers = {}
account_configs = {}  # {"alias": "config_path"}
default_account = None

# Shared secret required by every data endpoint. Set by init_readers' caller.
_auth_token = None


class AccountNotFound(Exception):
    pass


def set_auth_token(token):
    """Set the bearer token required by data endpoints."""
    global _auth_token
    _auth_token = token


def require_token(view):
    """Reject requests without the shared bearer token.

    Mailbox contents are account-owner data; an open port is not an
    authorization decision.

    The token is accepted ONLY in the Authorization header. A `?token=` query
    parameter is echoed verbatim into the access log (and into any proxy log or
    browser history in front of it), which turns every request into a written
    record of the secret.

    Both sides are compared as UTF-8 bytes: hmac.compare_digest raises TypeError
    on non-ASCII str, so a token containing one byte over 0x7f turned a failed
    auth attempt into a 500.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not _auth_token:
            return jsonify({"error": "gateway has no auth token configured"}), 503
        header = request.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer":
            return jsonify({"error": "unauthorized"}), 401
        sent = value.strip().encode("utf-8")
        expected = _auth_token.encode("utf-8")
        if not sent or not hmac.compare_digest(sent, expected):
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapper


@app.errorhandler(AccountNotFound)
def handle_account_not_found(e):
    return jsonify({"error": str(e), "accounts": sorted(readers)}), 404


def get_reader(account=None):
    """Resolve an account alias to its reader.

    Exact alias match only. Substring matching silently resolved '?account=a'
    to whichever alias happened to contain 'a', so a caller could be served a
    different mailbox than the one it asked for.
    """
    if account is None:
        account = request.args.get("account") or default_account
    if account is None:
        raise AccountNotFound("No account configured")
    if account in readers:
        return readers[account]
    raise AccountNotFound(f"Unknown account: {account!r}")


def init_readers(config_list):
    """Initialize readers from config file paths. Returns the alias list."""
    global default_account
    for config_path in config_list:
        config_path = config_path.strip()
        if not config_path:
            continue
        r = ProtonReader(config_path)
        # Alias: derive it from the config filename
        alias = os.path.basename(config_path)
        for suffix in ("_account.json", ".json"):
            if alias.endswith(suffix):
                alias = alias[: -len(suffix)]
                break
        if alias in readers:
            raise ValueError(f"Duplicate account alias {alias!r} from {config_path}")
        readers[alias] = r
        account_configs[alias] = config_path
        if default_account is None:
            default_account = alias
        log.info("account [%s] %s", alias, r.email)
    return sorted(readers)


def close_readers():
    """Release HTTP connections for every reader."""
    for r in readers.values():
        r.close()


# ─── Endpoints ───────────────────────────────────────────


@app.route("/")
def index():
    """Service description. No account data — this is the only open endpoint."""
    return jsonify({
        "service": "proton-mail-api gateway (read-only)",
        "auth": "Authorization: Bearer <token> (query-string tokens are rejected)",
        "endpoints": [
            {
                "method": "GET",
                "path": "/accounts",
                "description": "Configured account aliases and their primary emails",
            },
            {
                "method": "GET",
                "path": "/messages",
                "description": "List messages, newest first",
                "params": {
                    "account": "Account alias (default: first configured)",
                    "page": "Page number (default: 0)",
                    "size": "Messages per page, 1-150 (default: 20)",
                    "unread": "1 → only unread",
                    "q": "Search subject/sender via Proton's own filter",
                },
            },
            {
                "method": "GET",
                "path": "/messages/<msg_id>",
                "description": "Read one message and PGP-decrypt its body",
                "params": {"account": "(required) account alias"},
            },
            {
                "method": "GET",
                "path": "/recent",
                "description": "Newest messages across every account, merged and "
                               "sorted newest-first; each message carries its account",
                "params": {
                    "per_account": "Messages fetched per account, 1-150 (default: 10)",
                    "limit": "Total messages returned (default: 50)",
                    "decrypt": f"1 → also PGP-decrypt bodies (max {_DECRYPT_LIMIT} "
                               "messages; each body is a serialised operation)",
                },
            },
            {
                "method": "GET",
                "path": "/addresses",
                "description": "Addresses of one account, or every account with all=1",
                "params": {"account": "Account alias", "all": "1 → all accounts"},
            },
        ],
        "not_exposed": (
            "Verification-code extraction and all mutations (create/enable/"
            "disable/delete address, token refresh) are intentionally absent. "
            "Use the Python API or the proton-mail CLI for those."
        ),
    })


@app.route("/accounts")
@require_token
def accounts():
    return jsonify({
        "default": default_account,
        "accounts": {
            alias: {"email": r.email, "is_default": alias == default_account}
            for alias, r in sorted(readers.items())
        },
    })


@app.route("/messages")
@require_token
def messages():
    r = get_reader()
    try:
        size = int(request.args.get("size", 20))
        page = int(request.args.get("page", 0))
    except ValueError:
        return jsonify({"error": "page and size must be integers"}), 400
    if size < 1 or size > 150:
        return jsonify({"error": "size must be between 1 and 150"}), 400
    if page < 0:
        return jsonify({"error": "page must be >= 0"}), 400

    query = request.args.get("q", "").strip()
    if query:
        return jsonify(r.search(query, size=size))
    unread = request.args.get("unread", "0") == "1"
    return jsonify(r.inbox(page=page, size=size, unread_only=unread))


# How many accounts Proton is queried with at once. A sequential scan grows
# linearly with the account count (the first page can take seconds per
# account); keeping the pool bounded stops every account hitting 429 together.
_RECENT_WORKERS = 4

# A separate, low ceiling for decrypt=1: every body queues behind the single
# Node worker, so decrypting 50 messages would block the request for minutes.
_DECRYPT_LIMIT = 10


@app.route("/recent")
@require_token
def recent():
    """Newest messages across every configured account, merged and sorted.

    One request answers "what just arrived anywhere". Bodies are metadata-only
    by default: decrypting is serialised behind a single Node worker, so
    ?decrypt=1 is opt-in and capped separately.
    """
    try:
        per_account = int(request.args.get("per_account", 10))
        limit = int(request.args.get("limit", 50))
    except ValueError:
        return jsonify({"error": "per_account and limit must be integers"}), 400
    if not 1 <= per_account <= 150:
        return jsonify({"error": "per_account must be between 1 and 150"}), 400
    if limit < 1:
        return jsonify({"error": "limit must be >= 1"}), 400

    decrypt = request.args.get("decrypt", "0") == "1"
    if decrypt and limit > _DECRYPT_LIMIT:
        return jsonify({
            "error": f"decrypt=1 allows at most {_DECRYPT_LIMIT} messages "
                     f"(each one is a serialised PGP operation)",
        }), 400

    def fetch(item):
        alias, reader = item
        try:
            listing = reader.inbox(size=per_account)
        except (RuntimeError, httpx.HTTPError) as e:
            log.warning("recent: %s unavailable: %s", alias, e)
            return alias, None, "unavailable"
        for m in listing["messages"]:
            m["account"] = alias
        return alias, listing["messages"], None

    merged, errors = [], {}
    if readers:
        with ThreadPoolExecutor(max_workers=_RECENT_WORKERS) as pool:
            for alias, msgs, err in pool.map(fetch, sorted(readers.items())):
                if err:
                    errors[alias] = err
                else:
                    merged.extend(msgs)

    merged.sort(key=lambda m: m.get("time") or 0, reverse=True)
    merged = merged[:limit]

    if decrypt:
        for m in merged:
            try:
                full = readers[m["account"]].read(m["id"])
                m["body"] = full.get("body")
                m["mime_type"] = full.get("mime_type")
            except (RuntimeError, httpx.HTTPError) as e:
                log.warning("recent: decrypt failed for %s: %s", m["id"], e)
                m["body"] = None
                m["decrypt_error"] = "unavailable"

    return jsonify({
        "count": len(merged),
        "decrypted": decrypt,
        "messages": merged,
        "errors": errors,  # per-account breakage; detail stays in the log
    })


@app.route("/messages/<msg_id>")
@require_token
def read_message(msg_id):
    """Read one message.

    With several accounts configured the caller must name one: probing each
    until a read succeeds turns a single request into N authenticated API
    calls and can trigger every account's 401 → refresh → browser-login
    ladder. With exactly one account there is nothing to disambiguate, so
    requiring the parameter would just be a papercut.
    """
    account = request.args.get("account")
    if not account and len(readers) != 1:
        return jsonify({
            "error": "account parameter is required",
            "accounts": sorted(readers),
        }), 400
    return jsonify(get_reader(account).read(msg_id))


@app.route("/addresses")
@require_token
def addresses():
    if request.args.get("all", "0") == "1":
        # One account's failure must not blank the whole response; the error
        # detail stays in the log and no Proton API body leaks to the client.
        out = {}
        for alias, r in sorted(readers.items()):
            try:
                out[alias] = {"email": r.email, "addresses": r.addresses()}
            except (RuntimeError, httpx.HTTPError) as e:
                log.warning("addresses failed for %s: %s", alias, e)
                out[alias] = {"email": r.email, "error": "unavailable"}
        return jsonify({"accounts": out})
    r = get_reader()
    return jsonify({"addresses": r.addresses()})


# ProtonReader._api raises RuntimeError("API <path>: <status> — <body>") for
# every non-200. A bad message id is the caller's mistake, not ours, and
# answering 500 makes a client retry something that can never succeed.
_UPSTREAM_STATUS = re.compile(r"^API [^:]+: (4\d\d) —")


@app.errorhandler(Exception)
def handle_unexpected(e):
    """Log the detail, return a generic message.

    Reader exceptions embed API response bodies; forwarding them verbatim
    leaked Proton internals to the client.
    """
    from werkzeug.exceptions import HTTPException

    if isinstance(e, HTTPException):
        return e

    m = _UPSTREAM_STATUS.match(str(e))
    if m:
        status = int(m.group(1))
        # 401/403 are OUR credential problem, not the caller's: the stored
        # session went stale. Everything else 4xx is a bad request.
        if status not in (401, 403, 429):
            log.warning("upstream rejected %s: %s", request.path, e)
            return jsonify({"error": "bad request",
                            "upstream_status": status}), 400

    log.exception("unhandled error on %s", request.path)
    return jsonify({"error": "internal error", "type": type(e).__name__}), 500


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Proton Mail read-only gateway",
    )
    parser.add_argument("--port", type=int, default=5556, help="Port (default: 5556)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1 — binding 0.0.0.0 exposes mail to the network)",
    )
    parser.add_argument(
        "--configs",
        required=True,
        help="Comma-separated account config files",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("PROTON_GATEWAY_TOKEN"),
        help="Bearer token required by data endpoints "
             "(default: $PROTON_GATEWAY_TOKEN; generated if unset)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    token = args.token
    generated = False
    if not token:
        token = secrets.token_urlsafe(32)
        generated = True
    set_auth_token(token)

    aliases = init_readers(args.configs.split(","))
    if not aliases:
        print("No accounts configured", file=sys.stderr)
        return 2

    print(f"accounts: {', '.join(aliases)} (default: {default_account})")
    print(f"listening on http://{args.host}:{args.port}")
    if generated:
        print(f"generated auth token: {token}")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"WARNING: bound to {args.host} — mailbox contents are reachable "
            "from the network; the bearer token is the only protection.",
            file=sys.stderr,
        )

    try:
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
    finally:
        close_readers()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
