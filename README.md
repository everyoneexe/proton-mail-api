# proton-mail-api

Proton Mail HTTP API client with PGP decrypt, multi-account support, and
verification code extraction.

Proton has no IMAP/SMTP without their Bridge desktop app. This library talks to
the same HTTP API the web client uses, performs the SRP handshake, and decrypts
message bodies locally — so a script can read Proton mail without a browser
sitting open.

[![PyPI](https://img.shields.io/pypi/v/proton-mail-api)](https://pypi.org/project/proton-mail-api/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**[Full API reference → DOCS.md](DOCS.md)**

---

## ⚠️ Educational purposes

This project was written to **study** Proton's HTTP API, its SRP zero-knowledge
authentication, and its PGP key chain. Use it on accounts you own.

- Complying with Proton's [Terms and Conditions](https://proton.me/legal/terms)
  is your responsibility. This is an unofficial client: not supported,
  endorsed, or affiliated with Proton AG.
- Do not use it on accounts that are not yours. Not for bulk account creation,
  spam, unsolicited automation, or harvesting someone else's verification codes.
- The CAPTCHA solver exists to **study** the cases where Proton's human
  verification blocks this library — not as a bot-protection bypass tool.
- The API changes without notice. This code was written against behaviour
  observed on a specific date; it can break.
- No warranty. The author is not liable for data loss, account lockout, or
  suspension.

---

## Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Quick start](#quick-start)
- [Python API](#python-api)
- [Verification code extraction](#verification-code-extraction)
- [CLI](#cli)
- [Multi-account gateway](#multi-account-gateway-read-only)
- [How decrypt works](#how-decrypt-works)
- [Design notes](#design-notes)
- [Development](#development)
- [License](#license)

## What it does

- Read inbox over the HTTP API — no IMAP/SMTP, no Proton Bridge
- Decrypt PGP message bodies locally (`openpgp.js` via a persistent Node worker)
- SRP login from email + password; password never leaves the machine
- Wait for and extract verification codes, with an explicit refusal to guess
- Manage alias addresses: create, disable, enable, delete
- Multi-account read-only REST gateway (Flask)
- Auto-handle token expiry, rate limits, and insufficient-scope errors

Not implemented: **sending mail**, attachments, calendar, contacts, Proton Pass
aliases (a different API), and 2FA accounts (SRP completes but Proton then wants
a TOTP code).

## Install

Requires **Python ≥ 3.10** and **Node.js ≥ 18** (Node does the PGP work).

```bash
pip install proton-mail-api
```

Extras, by what you actually need:

| Extra | Install | For |
|---|---|---|
| `srp` | `pip install proton-mail-api[srp]` | Logging in with email + password |
| `captcha` | `pip install proton-mail-api[captcha]` | Solving Proton's puzzle CAPTCHA |
| `gateway` | `pip install proton-mail-api[gateway]` | The Flask REST gateway |
| `browser` | `pip install proton-mail-api[browser]` | Browser re-login fallback |
| `all` | `pip install proton-mail-api[all]` | Everything |

The `captcha` and `browser` extras also need a browser binary:

```bash
playwright install chromium
```

## Quick start

Two fields are enough:

```json
{
  "email": "you@proton.me",
  "password": "your-password"
}
```

```bash
chmod 600 account.json
proton-mail --config account.json login
```

`login` runs Proton's SRP handshake — the password is never sent, only a
zero-knowledge proof of it — then writes `uid`, `auth_token`, the
`AUTH`/`REFRESH` cookies, `key_salt`, `primary_key`, and `address_keys` back
into the file. From then on `refresh()` rotates the token by itself. The
password stays in the config because the PGP passphrase is
`bcrypt(password, key_salt)` — without it, bodies cannot be decrypted.

### When Proton asks for a CAPTCHA

Proton sometimes answers the login with human verification instead of a session
— **not always, and not predictably.** When it does, `login` falls back to a
browser, solves the drag-the-puzzle CAPTCHA, and takes the session cookies.

```bash
# Watch it happen
proton-mail --config account.json login --show-browser --slow-mo 300
```

Pass `allow_captcha=False` to refuse the browser fallback and get
`HumanVerificationRequired` instead — useful on a headless server where
launching Chromium is not acceptable.

### Existing session instead of a password

Accounts with 2FA cannot use `login`. Paste a browser session:

```json
{
  "email": "you@proton.me",
  "password": "your-password",
  "uid": "session-uid",
  "auth_token": "access-token",
  "cookies": {
    "AUTH-<uid>": "<token>",
    "REFRESH-<uid>": "<refresh-token>"
  }
}
```

```bash
proton-mail --config account.json setup   # fetch the keys for that session
```

## Python API

```python
from proton_mail_api import ProtonMailClient

with ProtonMailClient("account.json") as client:
    # Inbox
    msgs = client.inbox(size=10, unread_only=True)
    for m in msgs["messages"]:
        print(f"{m['from']}: {m['subject']}")

    # Read + decrypt
    msg = client.read(msgs["messages"][0]["id"])
    print(msg["body"])          # plaintext HTML

    # Server-side search over subject/sender
    print(client.search("verification", size=20)["messages"])

    # Wait for a verification code
    code = client.wait_code(
        to_filter="myalias@proton.me",
        from_filter="github",
        timeout=120,
    )
    print(code)                 # "123456" or None

    # Aliases (Business/Family plans — see the limits below)
    result = client.create_address("newalias42")
    client.disable_address(result["address_id"])
    client.enable_address(result["address_id"])
    client.delete_address(result["address_id"], email=result["email"])

    # Account info
    print(client.user_info())
    print(client.addresses())
    print(client.org_info())
```

`ProtonMailClient` holds a pooled HTTP connection — use it as a context manager
or call `client.close()`. Config files are rewritten **atomically** with mode
`0600`; they hold your password, session tokens, and PGP private keys.

Progress and retry messages go through `logging` under the `proton_mail_api`
logger. The library never prints to stdout.

### Verification code extraction

`wait_code()` returns `None` rather than guessing. A wrong code is worse than no
code: on `None` the caller can retry, on a wrong value it fails confusingly.

| Format | Example |
|---|---|
| Plain digits, 4–10 | `987654`, `12345678` |
| Evenly grouped | `552-392`, `123 456 789` |
| Split across HTML cells | `<td>4</td><td>8</td>…` |
| Alphanumeric (needs a context word) | `5KX2V`, `a1b2c3` |
| Context in 20+ languages | `Doğrulama kodunuz`, `验证码`, `인증번호`, `رمز التحقق` |

Deliberately **not** treated as codes: CSS values (`width:600400px`), colour
literals (`#123456`, `rgb(255 255 255)`), tracking URLs, order numbers, years,
and unevenly grouped phone numbers (`0850 123 45 67`). Style blocks, `<script>`,
HTML comments, and Outlook `[if mso]` blocks are stripped before matching, so a
code is never lifted out of markup.

Add a language by extending `ProtonReader._CODE_CTX` — one alternative per
phrase, nothing else to change.

## CLI

```bash
# Mail
proton-mail --config account.json inbox
proton-mail --config account.json inbox --unread --size 10
proton-mail --config account.json read <msg_id>
proton-mail --config account.json search "verification"
proton-mail --config account.json code --from github --timeout 120

# Session
proton-mail --config account.json login
proton-mail --config account.json login --show-browser --slow-mo 300
proton-mail --config account.json setup
proton-mail --config account.json refresh

# Account
proton-mail --config account.json user
proton-mail --config account.json addresses      # shows id + status
proton-mail --config account.json org

# Addresses
proton-mail --config account.json create-address mynewaddr
proton-mail --config account.json disable-address <address_id>
proton-mail --config account.json enable-address <address_id>
proton-mail --config account.json delete-address <address_id>
```

## Multi-account gateway (read-only)

The gateway is a **mail reader**: it lists and decrypts messages. It exposes no
verification-code endpoint and no mutations, on purpose. A URL that hands out
the current verification code for any address is an account-takeover primitive,
and create/delete/refresh do not belong on an unattended port.

Every data endpoint needs a bearer token, and the server binds `127.0.0.1`
unless you override `--host`. A `?token=` query parameter is **rejected** —
query strings land verbatim in access logs, proxy logs, and browser history.

```bash
export PROTON_GATEWAY_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python -m proton_mail_api.gateway --port 5556 \
  --configs account1.json,account2.json
```

| Endpoint | Purpose |
|---|---|
| `GET /` | Service info (open; no account data) |
| `GET /accounts` | Configured aliases + primary emails |
| `GET /messages?account=a&size=20&unread=1` | List messages |
| `GET /messages?account=a&q=verification` | Search subject/sender |
| `GET /messages/<msg_id>` | Read + PGP decrypt |
| `GET /recent?per_account=10&limit=50` | Newest across **all** accounts, merged |
| `GET /addresses?account=a` | Addresses; `all=1` for every account |

```bash
curl -H "Authorization: Bearer $PROTON_GATEWAY_TOKEN" \
  'http://127.0.0.1:5556/messages?account=account1&size=5'
```

`?account=` matches an alias **exactly** — a substring match could quietly read
the wrong mailbox. Aliases come from the config filename
(`business_account.json` → `business`). With a single account configured,
`?account=` is optional.

### `/recent` — one request across every account

Answers "what just arrived anywhere". Accounts are fetched through a bounded
pool of 4 workers, then merged newest-first; every message carries the `account`
it came from. A failing account is reported per-account instead of blanking the
response:

```json
{"count": 3, "decrypted": false,
 "messages": [{"id": "a1", "account": "business", "subject": "…", "time": 300}],
 "errors": {"wenox": "unavailable"}}
```

`?decrypt=1` also decrypts bodies, capped at **10** messages: each body is one
serialised PGP operation behind a single Node worker, so decrypting 50 would
block the request for minutes. For one body use `/messages/<id>`.

### Limits

Structural ceilings in this library:

| Ceiling | Value | Why |
|---|---|---|
| `PageSize` | 150 | Proton's own API maximum |
| `addresses()` pagination | unlimited | `max_pages=None`; stops at `Total` |
| `search()` pages | 10 | Loop guard; raise via `search(..., max_pages=N)` |
| `/recent?decrypt=1` | 10 messages | Serialised PGP operations |

Proton's own rules, which this library only reports:

- Creating an address needs the `organization` scope — a **Business/Family
  plan**. On a free plan the API never grants it, and `create_address` fails
  fast with `MissingScopes: ["organization"]`: no browser relaunch, no retry.
- **One deletion per year, per account.** Past that, `DELETE` is refused with
  `Code 2011`. Proton also refuses to delete an *enabled* address (`Code 2502`),
  so `delete_address` disables it first — and **re-enables it** if the delete is
  then refused, rather than leaving the alias silently switched off.

## How decrypt works

```
password + key_salt
  └─ bcrypt ──────────────→ key_password
                              └─ decrypt PrimaryKey
                                   └─ decrypt Token  (per-address passphrase)
                                        └─ decrypt AddressKey
                                             └─ decrypt body → plaintext HTML
```

Python derives the key password with `bcrypt`. The PGP operations run in
Node.js (`openpgp.js`) through a **persistent worker** speaking JSON lines over
stdin/stdout — roughly 5–10 ms per call, against 200–300 ms for spawning a
process each time. The worker restarts itself if it dies, and a reader thread
feeds a queue so a hung worker raises instead of blocking forever.

Why Node at all: Proton uses its own `openpgp.js` build, and the Python PGP
libraries do not handle Proton's `Token`-wrapped address keys correctly.
Hand-writing that crypto would be the worse option. The split is ~94% Python,
~5% JavaScript (229 lines, PGP only).

## Design notes

Decisions worth knowing before reading the source:

- **Login success is the `/core/v4/auth` verdict, not a cookie.** Proton writes
  an `AUTH-<uid>` cookie even for a *rejected* login (a pre-auth session), so
  cookie presence proves nothing. `Code: 1000` does.
- **Tokens come from `Set-Cookie`, not the JSON body.** Proton's success body
  carries `Code`, `UID`, `ServerProof`, and `Scope` — there is no `AccessToken`
  field. Tokens are bound to the *verified* UID by exact match, never by prefix.
- **The SRP modulus signature is verified.** `python-gnupg` returns data even
  for a bad signature, so the `valid` flag is checked explicitly; otherwise a
  hostile server could pick the group and SRP's guarantee collapses.
- **Plan-level scopes are not retried.** A missing `organization` scope means
  the plan lacks the feature, so re-login cannot help — failing in 0.2 s beats
  launching a browser for 15 s to get the same 403.
- **A failed re-login never overwrites a working config.** The new session is
  written only after it is confirmed.
- **The gateway maps upstream 4xx to 400.** A bad message id is the caller's
  mistake; answering 500 invites a retry that can never succeed. `401/403/429`
  stay 500 — those are *our* stale session, not a malformed request.

## Development

```bash
git clone https://github.com/everyoneexe/proton-mail-api
cd proton-mail-api
pip install -e '.[all]'
cd proton_mail_api/decrypt && npm install && cd -

pytest tests/ -q          # 165 tests, no network required
ruff check proton_mail_api tests
```

The test suite runs fully offline: HTTP is mocked with `httpx.MockTransport`,
the CAPTCHA solver is exercised against synthetic puzzle images, and Playwright
is stubbed so the browser paths are testable without a browser installed.

Tests assert observable behaviour, not implementation. If you add one, it should
fail for a plausible bug — not merely because the code changed.

## License

MIT — see [LICENSE](LICENSE).

Unofficial client. Not affiliated with, endorsed by, or supported by Proton AG.
