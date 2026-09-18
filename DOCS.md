# API reference

Complete reference for `proton-mail-api`. For the overview, install steps, and
design rationale see [README.md](README.md).

Every shape below is taken from the source, not idealised.

- [Getting a client](#getting-a-client)
- [Session](#session)
- [Reading mail](#reading-mail)
- [Verification codes](#verification-codes)
- [Account info](#account-info)
- [Addresses](#addresses)
- [Exceptions](#exceptions)
- [Config file](#config-file)
- [Gateway HTTP API](#gateway-http-api)
- [CLI reference](#cli-reference)
- [Logging](#logging)
- [Recipes](#recipes)

---

## Getting a client

```python
from proton_mail_api import ProtonMailClient

with ProtonMailClient("account.json") as client:
    ...
```

`ProtonMailClient` is an alias of `ProtonReader`. It holds one pooled
`httpx.Client`, so use it as a context manager or call `close()` — otherwise you
leak sockets.

```python
ProtonMailClient(config_path: str)
```

`config_path` may be relative; it is resolved against the current working
directory. The file is read immediately and rewritten (atomically, mode `0600`)
whenever the session changes.

### `close()`

Releases the HTTP connection. Does **not** stop the Node crypto worker — that is
process-wide and shared; call `stop_worker()` if you need it gone:

```python
from proton_mail_api import stop_worker
stop_worker()
```

---

## Session

### `login(allow_captcha=True, headless=None, slow_mo=0, keep_open=0)`

Opens a session from `email` + `password` and fetches every key. Needs the `srp`
extra.

| Parameter | Meaning |
|---|---|
| `allow_captcha` | `False` refuses the browser fallback and raises `HumanVerificationRequired` instead |
| `headless` | `None` reads `$PROTON_HEADLESS` (default headless); `False` shows the window |
| `slow_mo` | Milliseconds of delay per browser action, for watching the CAPTCHA solve |
| `keep_open` | Seconds to keep the browser open after a failure, for inspection |

Returns:

```python
{"uid": str, "email": str, "addresses": [str], "key_salt": bool,
 "method": "srp" | "captcha"}
```

`method` tells you which path succeeded: `"srp"` is pure HTTP, `"captcha"` means
Proton demanded human verification and a browser solved it.

Writes `uid`, `auth_token`, the `AUTH`/`REFRESH` cookies, `key_salt`,
`primary_key`, and `address_keys` into the config.

Raises `RuntimeError` on a rejected login (wrong password, non-existent account,
2FA enabled), `HumanVerificationRequired` when `allow_captcha=False`, and
`ImportError` if the `srp` extra is missing.

### `setup()`

Fetches keys for a session you already have (pasted cookies, or a 2FA account).
No password login is attempted.

```python
{"primary_key": bool, "key_salt": bool, "addresses": [str]}
```

### `refresh()`

Rotates the access token using the `REFRESH` cookie and writes the new session
back. Returns `True`.

You rarely call this: `_api()` refreshes on a 401 by itself, with a 60-second
cooldown so a burst of parallel requests triggers one refresh, not N.

---

## Reading mail

### `inbox(page=0, size=20, unread_only=False, label_id=0)`

```python
{"total": int, "page": int, "messages": [Message]}
```

`size` is clamped to `1..150` (Proton's own maximum). `label_id=0` is the inbox.

`Message`:

```python
{"id": str, "from": str, "from_name": str, "subject": str,
 "time": int,            # unix seconds
 "unread": bool, "size": int,
 "to": [str], "cc": [str]}
```

`to`/`cc` come from the listing response — reading them costs no extra request.

### `search(query, size=50, max_pages=10, label_id=0)`

Server-side search over subject and sender, using Proton's `Keyword` parameter.

```python
{"total": int, "query": str, "messages": [Message]}
```

`max_pages` is a loop guard, not a limit on matches — raise it if you expect
matches deep in the mailbox.

### `read(message_id)`

Fetches one message and decrypts its body.

```python
{"id": str, "from": str, "from_name": str, "to": [str],
 "subject": str, "time": int,
 "body": str,            # plaintext, usually HTML
 "mime_type": str}
```

Decryption tries the key for the `To:` address first, then every other address
key, then the primary key alone. If all fail, `body` holds a bracketed
diagnostic (`"[decrypt error: ...]"`) rather than raising — one unreadable
message should not abort a loop over a mailbox.

### `wait(subject=None, from_filter=None, to_filter=None, timeout=60, interval=3)`

Polls unread mail until one matches.

```python
{"found": bool, "message": Message | None}
```

All filters are case-insensitive substring matches, except `to_filter`, which
also matches sub-addresses: `to_filter="me@proton.me"` matches
`me+github@proton.me`, but **not** `other@proton.me`.

---

## Verification codes

### `wait_code(subject=None, from_filter=None, to_filter=None, timeout=120, interval=3)`

Waits for a matching mail, then extracts the code from its subject and body.

Returns the code as a `str`, or **`None`** — no mail arrived, or one arrived
with no recognisable code. It never guesses: on `None` you can retry, whereas a
wrong value fails somewhere confusing.

```python
code = client.wait_code(to_filter="signup@proton.me", from_filter="github")
if code is None:
    ...   # nothing usable arrived
```

Recognised shapes:

| Format | Example |
|---|---|
| Plain digits, 4–10 | `987654`, `12345678` |
| Evenly grouped | `552-392`, `123 456 789` |
| Split across HTML cells | `<td>4</td><td>8</td>…` |
| Alphanumeric (requires a context word) | `5KX2V`, `a1b2c3` |
| Context words in 20+ languages | `Doğrulama kodunuz`, `验证码`, `인증번호` |

Rejected on purpose: CSS values (`width:600400px`), colour literals
(`#123456`, `rgb(255 255 255)`), tracking URLs, order numbers, years, and
unevenly grouped phone numbers (`0850 123 45 67`). `<style>`, `<script>`, HTML
comments, and Outlook `[if mso]` blocks are stripped before matching, so a code
is never lifted out of markup.

To add a language, append one alternative to `ProtonReader._CODE_CTX`.

---

## Account info

### `user_info()`

```python
{"name": str, "email": str, "used_mb": int, "max_mb": int, "create_time": int}
```

### `addresses(use_cache=True)`

```python
[{"id": str, "email": str, "status": int, "type": int, "keys": int}]
```

| Field | Values |
|---|---|
| `status` | `1` enabled, `0` disabled (measured, not guessed) |
| `type` | `1` primary, `2` alias |
| `keys` | number of PGP keys on the address |

Cached for 5 minutes — Proton's first address page can take seconds. The cache
is dropped automatically by `create_address`, `disable_address`,
`enable_address`, and `delete_address`. Pass `use_cache=False` to force a fetch.

### `org_info()`

```python
{"name": str, "max_members": int, "max_addresses": int,
 "used_addresses": int, "max_domains": int, "used_domains": int}
```

Business/Family accounts only. On a personal plan the endpoint is not available.

---

## Addresses

> Creating an address requires the `organization` scope — a **Business or Family
> plan**. On a free plan the API never grants it and `create_address` fails fast
> with `MissingScopes: ["organization"]`.

### `create_address(local_part, domain="proton.me")`

Three steps: create the address, generate a PGP key for it, register that key.

```python
{"email": str, "address_id": str, "fingerprint": str}
```

The generated key is also written into `config["address_keys"]`, because
decryption only ever tries keys from there — an address missing from that map
cannot have its mail read until `setup()` runs again.

### `create_addresses_batch(names, domain="proton.me")`

```python
[{"email": str, "success": bool, ...}]   # plus create_address fields, or "error"
```

One failure does not abort the rest. Roughly 2–3 seconds per address.

### `disable_address(address_id)` / `enable_address(address_id)`

Stops / resumes mail delivery. Both drop the address cache so a later
`addresses()` reports the new `status` instead of a stale one.

### `delete_address(address_id, email=None)`

Deletes an alias. Pass `email` to also drop its local key; otherwise the key is
matched by `address_id`.

Two Proton rules are handled here:

- Proton refuses to delete an **enabled** address (`Code 2502`), so this
  disables it first.
- **Only one deletion per year, per account.** Past that the delete is refused
  with `Code 2011` — and because the disable already happened, the address
  would be left switched off. So a refused delete is **rolled back** with
  `enable_address`.

---

## Exceptions

| Exception | Raised when |
|---|---|
| `RuntimeError` | Any API error, rejected login, or missing config field |
| `HumanVerificationRequired` | Proton wants a CAPTCHA and `allow_captcha=False` |
| `ImportError` | An optional extra (`srp`, `captcha`, `browser`) is missing |
| `CaptchaError` | A CAPTCHA was present but could not be solved |
| `WorkerError` | A PGP operation failed (wrong key, bad input) |
| `WorkerUnavailable` | The Node worker itself is broken — retrying is pointless |

```python
from proton_mail_api import HumanVerificationRequired
from proton_mail_api.captcha import CaptchaError
from proton_mail_api.crypto_worker import WorkerError, WorkerUnavailable
```

`HumanVerificationRequired` carries Proton's `Details` payload on `.details`.

API errors are formatted as
`API <path>: <status> — <body>`, so the upstream status is recoverable:

```python
try:
    client.create_address("x")
except RuntimeError as e:
    if "MissingScopes" in str(e):
        ...   # plan does not include it; retrying will not help
```

---

## Config file

Minimum — everything else is filled in by `login()`:

```json
{
  "email": "you@proton.me",
  "password": "your-password"
}
```

After login:

| Key | Purpose |
|---|---|
| `email`, `password` | Credentials; the password is kept because the PGP passphrase is `bcrypt(password, key_salt)` |
| `uid`, `auth_token` | Current session |
| `cookies` | `AUTH-<uid>`, `REFRESH-<uid>`, plus `Session-Id` (the refresh endpoint needs it) |
| `key_salt` | bcrypt salt for the key password |
| `primary_key` | Armoured PGP private key |
| `address_keys` | Per-address `{address_id, private_key, token, fingerprint}` |

The file is rewritten atomically with mode `0600`. It holds your password,
session tokens, and private keys — treat it like an SSH key. `.gitignore`
already excludes `account.json` and `*_account.json`.

---

## Gateway HTTP API

```bash
export PROTON_GATEWAY_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python -m proton_mail_api.gateway --port 5556 --configs a.json,b.json
```

Flags: `--port` (5556), `--host` (`127.0.0.1`), `--configs` (comma-separated),
`--token` (defaults to `$PROTON_GATEWAY_TOKEN`, generated and printed if unset).

Auth: `Authorization: Bearer <token>` on every endpoint except `/`. A `?token=`
query parameter is **rejected** — query strings land in access logs, proxy logs,
and browser history.

| Endpoint | Query parameters |
|---|---|
| `GET /` | — (open; no account data) |
| `GET /accounts` | — |
| `GET /messages` | `account`, `page`, `size` (1–150), `unread=1`, `q` |
| `GET /messages/<id>` | `account` (optional with a single account) |
| `GET /recent` | `per_account` (10), `limit` (50), `decrypt=1` (max 10) |
| `GET /addresses` | `account`, `all=1` |

`?account=` matches an alias **exactly** — a substring match could quietly read
the wrong mailbox. Aliases come from the config filename:
`business_account.json` → `business`.

Status codes:

| Code | Meaning |
|---|---|
| 400 | Bad request — invalid paging, or the upstream rejected it (`upstream_status` in the body) |
| 401 | Missing or wrong bearer token |
| 404 | Unknown account, or an endpoint that does not exist |
| 500 | Our problem — stale session (upstream 401/403/429) or an unexpected error |

`/recent` reports per-account failures instead of blanking the response:

```json
{"count": 3, "decrypted": false,
 "messages": [{"id": "a1", "account": "business", "subject": "…", "time": 300}],
 "errors": {"wenox": "unavailable"}}
```

**Not exposed, deliberately:** verification-code extraction and every mutation
(create/enable/disable/delete address, token refresh). A URL that hands out the
current code for any address is an account-takeover primitive. Use the Python
API or CLI.

### Using it from FastAPI

The client is synchronous and uses `time.sleep`, so it must **not** run inside
`async def` — it would block the event loop. A plain `def` handler is dispatched
to a threadpool by Starlette and works:

```python
from fastapi import FastAPI
from proton_mail_api import ProtonMailClient

app = FastAPI()
client = ProtonMailClient("account.json")

@app.get("/messages")          # def, NOT async def
def messages(size: int = 20):
    return client.inbox(size=size)
```

---

## CLI reference

```
proton-mail --config FILE [--verbose] COMMAND
```

| Command | Arguments |
|---|---|
| `inbox` | `--size N`, `--unread` |
| `read` | `<msg_id>` |
| `search` | `<query>` |
| `wait` | `--subject`, `--from`, `--timeout` |
| `code` | `--subject`, `--from`, `--timeout` |
| `login` | `--show-browser`, `--slow-mo MS`, `--keep-open SEC` |
| `setup` | — |
| `refresh` | — |
| `user` | — |
| `addresses` | — (prints id + status) |
| `org` | — |
| `create-address` | `<name>`, `--domain` |
| `disable-address` | `<address_id>` |
| `enable-address` | `<address_id>` |
| `delete-address` | `<address_id>` |

---

## Logging

Nothing is printed to stdout by the library; everything goes through `logging`
under `proton_mail_api`:

```python
import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
```

`INFO` reports logins, token refreshes, and key updates. `WARNING` reports rate
limits and per-account failures. `DEBUG` adds browser console output when the
CAPTCHA solver runs.

CAPTCHA diagnostics are written to disk when the solver runs:
`/tmp/proton-captcha-bg.png` (raw background) and
`/tmp/proton-captcha-detected.png` (detected hole marked). A failed browser
login also leaves `/tmp/proton-login-failed.png`.

---

## Recipes

**Wait for a signup code on a specific alias**

```python
with ProtonMailClient("account.json") as c:
    code = c.wait_code(to_filter="signup+github@proton.me", timeout=180)
```

**Poll several accounts with one HTTP call**

```bash
curl -H "Authorization: Bearer $PROTON_GATEWAY_TOKEN" \
  'http://127.0.0.1:5556/recent?per_account=5&limit=20'
```

**Read every unread message, decrypted**

```python
with ProtonMailClient("account.json") as c:
    for m in c.inbox(size=50, unread_only=True)["messages"]:
        print(m["subject"], "->", c.read(m["id"])["body"][:200])
```

**Refuse the browser on a headless server**

```python
from proton_mail_api import HumanVerificationRequired

try:
    client.login(allow_captcha=False)
except HumanVerificationRequired:
    ...   # Proton wants a CAPTCHA; handle it out of band
```

**Create an alias and use it immediately** (Business/Family)

```python
alias = client.create_address("signup42")
code = client.wait_code(to_filter=alias["email"], timeout=180)
```
