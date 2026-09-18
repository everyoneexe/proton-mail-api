"""Behavioural tests for the client, code extraction, and the gateway surface."""

import base64
import json
import os
import pathlib
import stat
import sys
import time
import types

import pytest

from proton_mail_api import ProtonMailClient, ProtonReader


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "account.json"
    path.write_text(json.dumps({
        "uid": "test-uid",
        "auth_token": "test-token",
        "email": "test@proton.me",
        "password": "test-pass",
        "key_salt": "",
        "cookies": {"AUTH-test-uid": "test-token"},
        "address_keys": {},
    }))
    return str(path)


@pytest.fixture
def client(config_path):
    with ProtonMailClient(config_path) as c:
        yield c


def test_public_alias_is_the_reader():
    assert ProtonMailClient is ProtonReader


# -- config loading ---------------------------------------------------
#
# A missing or malformed config is a setup mistake. Reporting it as a raw
# traceback through open()/json.load() buries the one fact the user needs.


def test_a_missing_config_names_the_path_and_the_fix(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(FileNotFoundError) as e:
        ProtonMailClient(str(missing))
    msg = str(e.value)
    assert str(missing) in msg
    assert "login" in msg, "the message must say how to populate the file"


def test_a_malformed_config_reports_the_json_position(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text('{"email": "a@b.c",}')
    with pytest.raises(ValueError, match="not valid JSON") as e:
        ProtonMailClient(str(broken))
    assert "line" in str(e.value) and "column" in str(e.value)


def test_a_config_without_usable_credentials_is_refused(tmp_path):
    """Neither a session nor a password means nothing can be done with it."""
    empty = tmp_path / "empty.json"
    empty.write_text('{"email": "a@b.c"}')
    with pytest.raises(ValueError, match="email\\+password"):
        ProtonMailClient(str(empty))


# -- portability ------------------------------------------------------
#
# The package claims OS Independent. Three things used to break that: os.fchmod
# does not exist on Windows, diagnostics were written to a literal /tmp, and a
# bare "node" handed to Popen never finds an nvm/fnm `node.cmd` shim.


def test_config_is_saved_where_fchmod_does_not_exist(client, monkeypatch):
    """Windows has no os.fchmod; losing the session there is not acceptable."""
    monkeypatch.delattr(os, "fchmod", raising=False)

    client.config["uid"] = "saved-without-fchmod"
    client._save_config()

    on_disk = json.loads(pathlib.Path(client.config_path).read_text())
    assert on_disk["uid"] == "saved-without-fchmod"


def test_a_failed_save_leaves_no_temp_file_behind(client, monkeypatch):
    """A crash mid-write must not litter the config directory."""
    def boom(*a, **kw):
        raise RuntimeError("disk full")

    monkeypatch.setattr(json, "dump", boom)
    with pytest.raises(RuntimeError, match="disk full"):
        client._save_config()

    directory = pathlib.Path(client.config_path).parent
    assert list(directory.glob(".proton-config-*")) == []


def test_diagnostics_go_to_the_platform_temp_dir():
    """A literal /tmp does not exist on Windows."""
    import tempfile as _tempfile

    from proton_mail_api.captcha import PuzzleSolver

    for path in (PuzzleSolver.DEBUG_BG, PuzzleSolver.DEBUG_MARKED):
        assert path.startswith(_tempfile.gettempdir())
        assert path != os.path.join("/tmp", os.path.basename(path)) or \
            _tempfile.gettempdir() == "/tmp"


def test_node_is_resolved_through_which_not_handed_to_popen():
    """Popen does not expand %PATHEXT%, so `node.cmd` on Windows needs which."""
    from proton_mail_api.crypto_worker import _resolve_node

    resolved = _resolve_node()
    # Either an absolute path from which(), or the bare name when Node is
    # absent — so start() can still raise its install hint.
    assert os.path.isabs(resolved) or resolved == "node"


def test_an_explicit_node_binary_wins(monkeypatch):
    """nvm/fnm shells often never export node onto PATH."""
    from proton_mail_api import crypto_worker

    monkeypatch.setenv("PROTON_NODE_BIN", "/opt/custom/node")
    assert crypto_worker._resolve_node() == "/opt/custom/node"


def test_auth_headers_track_the_current_token(client):
    """Callers rely on the shared client carrying the live token."""
    assert client._http.headers["x-pm-uid"] == "test-uid"
    assert client._http.headers["Authorization"] == "Bearer test-token"

    client.uid = "rotated-uid"
    client.auth_token = "rotated-token"
    client.config["cookies"] = {"AUTH-rotated-uid": "rotated-token"}
    client._sync_client_auth()

    assert client._http.headers["x-pm-uid"] == "rotated-uid"
    assert client._http.headers["Authorization"] == "Bearer rotated-token"
    # Stale cookies must not linger; Proton rejects a mismatched session.
    assert "AUTH-test-uid" not in client._http.cookies
    assert client._http.cookies["AUTH-rotated-uid"] == "rotated-token"


def test_save_config_is_private_and_atomic(client, config_path):
    client.config["key_salt"] = "abc"
    client._save_config()

    # POSIX permission bits are not enforced on Windows. os.fchmod exists
    # there -- measured on CI -- but the mode still reads back 0o666, so
    # hasattr is the wrong gate; os.name is the honest one.
    if os.name == "posix":
        mode = stat.S_IMODE(os.stat(config_path).st_mode)
        assert mode == 0o600, f"secrets world-readable: {oct(mode)}"

    with open(config_path) as f:
        assert json.load(f)["key_salt"] == "abc"
    # No temp file left behind.
    leftovers = [n for n in os.listdir(os.path.dirname(config_path))
                 if n.startswith(".proton-config-")]
    assert leftovers == []


def test_save_config_keeps_old_content_when_serialization_fails(client, config_path):
    with open(config_path) as f:
        before = f.read()
    client.config["bad"] = {1, 2}  # sets are not JSON-serializable
    with pytest.raises(TypeError):
        client._save_config()
    with open(config_path) as f:
        assert f.read() == before, "truncated config on failed write"



@pytest.mark.parametrize("subject,body,expected", [
    # Full length must survive — a 6-digit code truncated to 4 is a wrong code.
    ("", "Your verification code: 987654", "987654"),
    ("", "otp 12345678", "12345678"),
    ("", "1234567 is your verification code", "1234567"),
    ("Your GitHub verification code", "<p>Code: 123456</p>", "123456"),
    ("Your code is 0042", "", "0042"),
    ("", "2FA code&nbsp;<b>8812</b>", "8812"),
    ("483920 is your Instagram code", "<p>Hi there, tap to confirm.</p>", "483920"),
    ("", '<p>Enter "839201" to continue</p>', "839201"),
    ("", "<p>[772211] Confirm your email</p>", "772211"),
    ("", "<p>Verification code:</p>\n<h1>661234</h1>", "661234"),
    # Grouped forms are normalised to digits.
    ("Sign in", "Your one-time passcode is 552-392", "552392"),
    ("", "<div>Enter 123 456 789 to verify</div>", "123456789"),
    ("", "<p>Code:&nbsp;&nbsp;483&nbsp;920</p>", "483920"),
])
def test_extract_code_numeric(client, subject, body, expected):
    assert client._extract_code(subject, body) == expected


@pytest.mark.parametrize("body,expected", [
    # Services split the code across table cells / spans so it renders as boxes.
    (("<table><tr><td>4</td><td>8</td><td>3</td><td>9</td><td>2</td><td>0</td></tr>"
      "</table><p>Enter the code above</p>"), "483920"),
    (("<div><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>"
      "<span>6</span></div><p>verification code</p>"), "123456"),
    ("<p>Code: <b>48</b><b>39</b><b>20</b></p>", "483920"),
])
def test_extract_code_from_split_cells(client, body, expected):
    assert client._extract_code("", body) == expected


@pytest.mark.parametrize("body,expected", [
    ("<p>Your Steam Guard code is 5KX2V</p>", "5KX2V"),
    ("<p>Your login code: a1b2c3</p>", "a1b2c3"),
])
def test_extract_alphanumeric_code(client, body, expected):
    """Not every service sends digits."""
    assert client._extract_code("", body) == expected


@pytest.mark.parametrize("body,expected", [
    # Shapes taken from how real providers actually wrap mail.
    ('<div dir="ltr"><div class="gmail_quote"><p>Your code is 918273</p></div></div>',
     "918273"),
    # Hidden preheader text sits before the real content and is full of numbers.
    (('<span style="display:none">Order 40281 shipped 2026</span>'
      "<p>Verification code: 771122</p>"), "771122"),
    ("<p>Code 445566</p><footer><p>© 2026 Acme, suite 4100</p></footer>", "445566"),
    ('<p>Click <a href="https://x.com/v/778899">778899</a> to verify</p>', "778899"),
    ('<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="><p>Your code: 334455</p>',
     "334455"),
    ("<p>Ref 987654321098765 — your verification code is 556677</p>", "556677"),
    ("<p>CODE: 224466</p>", "224466"),
    # A sentence-final period is not a decimal point.
    ("<p>Your verification code is 889900.</p>", "889900"),
    ("<h1>552104</h1><p>Use this to sign in</p>", "552104"),
    ('<p dir="rtl">رمز التحقق: 123987</p>', "123987"),
    ("<p>Kodunuz:</p><p>&nbsp;446688</p>", "446688"),
])
def test_extract_code_from_realistic_bodies(client, body, expected):
    assert client._extract_code("", body) == expected


def test_context_adjacent_code_wins_over_a_bare_number(client):
    """Two candidates: the one next to the context word is the code."""
    body = "<p>Ignore 999999. Your verification code is 123321</p>"
    assert client._extract_code("", body) == "123321"

@pytest.mark.parametrize("body,expected", [
    ("<p>Doğrulama kodunuz: 483920</p>", "483920"),
    ("<p>Tu código de verificación es 728391</p>", "728391"),
    ("<p>Ihr Bestätigungscode lautet 552104</p>", "552104"),
    ("<p>Votre code de vérification est 903211</p>", "903211"),
    ("<p>Ваш код подтверждения: 471209</p>", "471209"),
    ("<p>您的验证码是 839201</p>", "839201"),
    ("<p>認証コードは 774512 です</p>", "774512"),
    ("<p>인증번호 [201948] 입니다</p>", "201948"),
    ("<p>Seu código de verificação: 118822</p>", "118822"),
    ("<p>رمز التحقق الخاص بك هو 664422</p>", "664422"),
    ("<p>Twój kod weryfikacyjny: 330099</p>", "330099"),
    ("<p>Kode verifikasi Anda 445599</p>", "445599"),
    ("<p>Mã xác minh của bạn là 778811</p>", "778811"),
    ("<p>Je verificatiecode is 220044</p>", "220044"),
    ("<p>Il tuo codice di verifica è 909122</p>", "909122"),
])
def test_extract_code_is_not_english_only(client, body, expected):
    assert client._extract_code("", body) == expected


@pytest.mark.parametrize("body", [
    # Inline styles, style blocks, comments, at-rules — digits in CSS are layout,
    # never codes. Returning one of these as "the code" is worse than failing.
    '<td style="width:600400px;padding:0"><p>Hello</p></td>',
    '<style type="text/css">\n.btn { max-width: 600500px; }\n</style><p>Hi</p>',
    "<style>div > p { margin: 120000 340000 }</style><p>Merhaba</p>",
    "<!--[if mso]><style>td{width:999888}</style><![endif]--><p>Hello</p>",
    "<!-- .foo { padding: 1234 5678 } --><p>Welcome</p>",
    "<style>@media only screen and (max-width:600000px){.x{display:none}}</style><p>Hey</p>",
    '<div style="--token:998877">Body text</div>',
    '<div class="col-123456 row-7788"><p>Nothing</p></div>',
    "<style>.a{font:12px/1.5 Arial;letter-spacing:123 456}</style><p>Text</p>",
    # Unclosed style tag: tag stripping alone leaves the CSS as plain text.
    "<style>.a{width:123456;}<p>Hello</p>",
    "<!-- if a > b then .x{w:445566} --><p>Hi</p>",
    ".btn { max-width: 604800; }",
    "<script>var t=987654;</script><p>Hello</p>",
    # Colour literals and dimensioned values are not codes.
    "<p>Brand color is #123456 across the app</p>",
    "<p>Use #12345678 as the tint</p>",
    "<p>Accent rgb(255 255 255) is used</p>",
    "<p>hsl(210 100% 50%) and hsl(123456)</p>",
    "<p>The banner is 600000px wide</p>",
])
def test_css_is_never_reported_as_a_code(client, body):
    assert client._extract_code("", body) is None


@pytest.mark.parametrize("body", [
    "<p>Welcome to our 2026 newsletter! Read our top 10 stories.</p>",
    "<p>Order 40281 shipped. Tracking 1Z999AA10123456784.</p>",
    "<p>Hi Ahmet, your account is ready. Log in anytime.</p>",
    "<table><tr><td>19.99</td><td>24.99</td><td>29.99</td><td>34.99</td></tr></table>",
    "<p>Your Account2 code settings changed</p>",
    "<p>Please Verify2FA in settings</p>",
    "<p>Meeting on 2026-09-18 at 14:30</p>",
    # Phone numbers group unevenly; codes group evenly.
    "<p>Call us at 0850 123 45 67</p>",
    "<p>No numbers here at all.</p>",
    "<p>Order #40281 https://x.com/track/5551212</p>",
])
def test_mail_without_a_code_returns_none(client, body):
    """A wrong code is worse than no code — callers can retry on None."""
    assert client._extract_code("Invoice 2026 receipt", body) is None


def test_subaddress_filter_does_not_match_a_different_tag(client):
    """foo+a@x and foo+b@x are different inboxes for the caller's purposes."""
    assert client._addr_base_match("foo@x.com", ["foo+tag@x.com"]) is True
    assert client._addr_base_match("foo@x.com", ["bar@x.com"]) is False


def test_browser_login_is_rate_limited(client, monkeypatch):
    """One unauthorized token must not spawn a browser per request.

    The 403-scope path calls _browser_relogin on every failing request; without
    a cooldown inside the method each one launched a headless Chromium.
    """
    launches = []

    def fake_run(coro):
        coro.close()  # never execute the Playwright body
        launches.append(1)
        # _browser_relogin unpacks (uid, scope, cookies) and writes the config.
        return "browser-uid", "full mail", {"AUTH-browser-uid": "browser-access"}

    monkeypatch.setattr("asyncio.run", fake_run)
    # The cooldown is pure bookkeeping — it must be testable without the
    # optional browser extra installed.
    playwright = types.ModuleType("playwright")
    async_api = types.ModuleType("playwright.async_api")
    async_api.async_playwright = lambda: None
    async_api.Error = type("Error", (Exception,), {})
    playwright.async_api = async_api
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)

    assert client._browser_relogin() is True
    assert client._browser_relogin() is False, "second login not rate limited"
    assert client._browser_relogin() is False
    assert len(launches) == 1

    # Once the window passes, a login is allowed again.
    client._last_browser_login_time -= client._BROWSER_LOGIN_COOLDOWN + 1
    assert client._browser_relogin() is True
    assert len(launches) == 2


# ── gateway ─────────────────────────────────────────────────────────


@pytest.fixture
def gateway(config_path, monkeypatch):
    from proton_mail_api import gateway as gw

    monkeypatch.setattr(gw, "readers", {}, raising=False)
    monkeypatch.setattr(gw, "account_configs", {}, raising=False)
    monkeypatch.setattr(gw, "default_account", None, raising=False)
    gw.init_readers([config_path])
    gw.set_auth_token("s3cret")
    app = gw.app
    app.config.update(TESTING=True)
    try:
        yield app.test_client()
    finally:
        gw.close_readers()
        gw.set_auth_token(None)


def test_gateway_root_needs_no_token_and_exposes_no_accounts(gateway):
    r = gateway.get("/")
    assert r.status_code == 200
    assert "proton.me" not in r.get_data(as_text=True)


@pytest.mark.parametrize("path", ["/accounts", "/messages", "/addresses",
                                  "/messages/abc123"])
def test_gateway_data_endpoints_reject_missing_token(gateway, path):
    assert gateway.get(path).status_code == 401


AUTH = {"Authorization": "Bearer s3cret"}


def test_gateway_rejects_wrong_token(gateway):
    assert gateway.get("/accounts", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_gateway_accepts_bearer_header(gateway):
    r = gateway.get("/accounts", headers=AUTH)
    assert r.status_code == 200
    assert r.get_json()["accounts"]["account"]["email"] == "test@proton.me"


def test_query_string_token_is_not_accepted(gateway):
    """A ?token= value is written verbatim into access/proxy logs."""
    assert gateway.get("/accounts?token=s3cret").status_code == 401


@pytest.mark.parametrize("header", [
    "s3cret",             # no scheme
    "Basic s3cret",       # wrong scheme
    "Bearer",             # scheme only
    "Bearer ",            # empty credential
])
def test_malformed_authorization_headers_are_rejected(gateway, header):
    assert gateway.get("/accounts", headers={"Authorization": header}).status_code == 401


def test_non_ascii_token_is_rejected_not_a_server_error(gateway):
    """hmac.compare_digest raises TypeError on non-ASCII str.

    Comparing str turned a failed auth attempt into a 500, which both leaks that
    the comparison path was reached and breaks any non-ASCII token.
    """
    r = gateway.get("/accounts", headers={"Authorization": "Bearer ünicode-tökén"})
    assert r.status_code == 401, "non-ASCII token must fail auth, not crash"


def test_lowercase_bearer_scheme_is_accepted(gateway):
    """RFC 7235 auth schemes are case-insensitive."""
    r = gateway.get("/accounts", headers={"Authorization": "bearer s3cret"})
    assert r.status_code == 200


@pytest.mark.parametrize("path", [
    "/code", "/wait", "/inbox", "/read/abc", "/create-address",
    "/create-addresses", "/refresh", "/unused", "/addresses/all",
])
def test_removed_endpoints_are_gone(gateway, path):
    """Code extraction and mutations must not be reachable over HTTP."""
    r = gateway.get(path, headers=AUTH)
    assert r.status_code == 404, f"{path} still routed"
    r = gateway.post(path, headers=AUTH)
    assert r.status_code in (404, 405), f"{path} still routed for POST"


def test_unknown_account_is_not_substring_matched(gateway):
    """'acc' must not silently resolve to the 'account' mailbox."""
    r = gateway.get("/messages?account=acc", headers=AUTH)
    assert r.status_code == 404
    assert r.get_json()["accounts"] == ["account"]


@pytest.mark.parametrize("query,expected", [
    ("size=0", 400),
    ("size=999", 400),
    ("page=-1", 400),
    ("size=abc", 400),
])
def test_messages_validates_paging(gateway, query, expected):
    assert gateway.get(f"/messages?{query}", headers=AUTH).status_code == expected


def test_read_message_uses_the_only_account_implicitly(gateway):
    """One configured account leaves nothing to disambiguate."""
    r = gateway.get("/messages/abc123", headers=AUTH)
    assert r.status_code != 400, r.get_json()


def test_read_message_requires_an_account_when_several_exist(gateway,
                                                             monkeypatch):
    """Probing every account would fan one request out to N mailboxes."""
    from proton_mail_api import gateway as gw

    monkeypatch.setitem(gw.readers, "second",
                        _StubReader("second@proton.me", []))
    r = gateway.get("/messages/abc123", headers=AUTH)
    assert r.status_code == 400
    assert "account" in r.get_json()["error"]
    assert sorted(r.get_json()["accounts"]) == ["account", "second"]


def test_an_upstream_client_error_is_not_reported_as_a_server_error(gateway,
                                                                    monkeypatch):
    """A bad message id is the caller's mistake; 500 invites a pointless retry."""
    from proton_mail_api import gateway as gw

    def reject(msg_id):
        raise RuntimeError(
            "API /mail/v4/messages/deadbeef: 400 — "
            '{"Code":2061,"Error":"Attribute ID is invalid"}'
        )

    monkeypatch.setattr(gw.readers["account"], "read", reject)
    r = gateway.get("/messages/deadbeef", headers=AUTH)
    assert r.status_code == 400
    body = r.get_json()
    assert body["upstream_status"] == 400
    # The upstream body carries Proton internals and must not be echoed.
    assert "Attribute ID" not in r.get_data(as_text=True)


@pytest.mark.parametrize("status", [401, 403, 429])
def test_our_own_credential_failures_stay_server_side(gateway, monkeypatch,
                                                       status):
    """A stale stored session is our problem, not a malformed request."""
    from proton_mail_api import gateway as gw

    def reject(msg_id):
        raise RuntimeError(f"API /mail/v4/messages/x: {status} — denied")

    monkeypatch.setattr(gw.readers["account"], "read", reject)
    assert gateway.get("/messages/x", headers=AUTH).status_code == 500


# ── /recent ─────────────────────────────────────────────────────────


class _StubReader:
    """Stands in for ProtonReader so /recent is tested without network."""

    def __init__(self, email, messages, fail=False):
        self.email = email
        self._messages = messages
        self._fail = fail
        self.inbox_sizes = []

    def inbox(self, page=0, size=20, unread_only=False, label_id=0):
        if self._fail:
            raise RuntimeError("API /mail/v4/messages: 403 — scope")
        self.inbox_sizes.append(size)
        return {"total": len(self._messages), "page": page,
                "messages": [dict(m) for m in self._messages[:size]]}

    def read(self, msg_id):
        return {"id": msg_id, "body": f"<p>decrypted {msg_id}</p>",
                "mime_type": "text/html"}

    def close(self):
        pass


def _msg(mid, t):
    return {"id": mid, "from": "x@y.com", "subject": mid, "time": t,
            "unread": True, "size": 1, "to": [], "cc": []}


@pytest.fixture
def recent_gateway(monkeypatch):
    from proton_mail_api import gateway as gw

    stubs = {
        "acc_a": _StubReader("a@proton.me", [_msg("a1", 300), _msg("a2", 100)]),
        "acc_b": _StubReader("b@proton.me", [_msg("b1", 200)]),
        "acc_dead": _StubReader("d@proton.me", [], fail=True),
    }
    monkeypatch.setattr(gw, "readers", stubs, raising=False)
    monkeypatch.setattr(gw, "default_account", "acc_a", raising=False)
    gw.set_auth_token("s3cret")
    gw.app.config.update(TESTING=True)
    try:
        yield gw.app.test_client(), stubs
    finally:
        gw.set_auth_token(None)


def test_recent_merges_accounts_newest_first(recent_gateway):
    client, _ = recent_gateway
    r = client.get("/recent", headers=AUTH)
    assert r.status_code == 200
    body = r.get_json()
    assert [m["id"] for m in body["messages"]] == ["a1", "b1", "a2"]
    # Every message says which mailbox it came from.
    assert [m["account"] for m in body["messages"]] == ["acc_a", "acc_b", "acc_a"]


def test_recent_requires_a_token(recent_gateway):
    client, _ = recent_gateway
    assert client.get("/recent").status_code == 401


def test_recent_reports_failing_accounts_without_failing_the_request(recent_gateway):
    """One dead config must not blank out every other mailbox."""
    client, _ = recent_gateway
    body = client.get("/recent", headers=AUTH).get_json()
    assert body["errors"] == {"acc_dead": "unavailable"}
    assert len(body["messages"]) == 3


def test_recent_limit_truncates_after_merging(recent_gateway):
    """limit applies to the merged list, so the newest overall wins."""
    client, _ = recent_gateway
    body = client.get("/recent?limit=2", headers=AUTH).get_json()
    assert [m["id"] for m in body["messages"]] == ["a1", "b1"]
    assert body["count"] == 2


def test_recent_per_account_is_passed_through(recent_gateway):
    client, stubs = recent_gateway
    client.get("/recent?per_account=1", headers=AUTH)
    assert stubs["acc_a"].inbox_sizes == [1]


def test_recent_does_not_decrypt_by_default(recent_gateway):
    """Decrypting is serialised behind one Node worker — never implicit."""
    client, _ = recent_gateway
    body = client.get("/recent", headers=AUTH).get_json()
    assert body["decrypted"] is False
    assert all("body" not in m for m in body["messages"])


def test_recent_decrypt_opt_in_returns_bodies(recent_gateway):
    client, _ = recent_gateway
    body = client.get("/recent?decrypt=1&limit=2", headers=AUTH).get_json()
    assert body["decrypted"] is True
    assert body["messages"][0]["body"] == "<p>decrypted a1</p>"


def test_recent_decrypt_rejects_an_unbounded_limit(recent_gateway):
    """A 50-message decrypt would block the request for minutes."""
    client, _ = recent_gateway
    r = client.get("/recent?decrypt=1&limit=50", headers=AUTH)
    assert r.status_code == 400
    assert "decrypt" in r.get_json()["error"]


@pytest.mark.parametrize("query", ["per_account=0", "per_account=999",
                                   "limit=0", "limit=abc", "per_account=x"])
def test_recent_validates_paging(recent_gateway, query):
    client, _ = recent_gateway
    assert client.get(f"/recent?{query}", headers=AUTH).status_code == 400


# ── email+password login ────────────────────────────────────────────


def test_config_with_only_email_and_password_is_valid(tmp_path):
    """A fresh config needs no cookies — login() opens the session."""
    path = tmp_path / "fresh.json"
    path.write_text(json.dumps({"email": "a@proton.me", "password": "pw"}))
    with ProtonMailClient(str(path)) as c:
        assert c.email == "a@proton.me"
        assert c.uid == ""


def test_config_without_any_credentials_is_rejected(tmp_path):
    """Silently loading an unusable config just defers the failure."""
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"email": "a@proton.me"}))
    with pytest.raises(ValueError, match="email\\+password"):
        ProtonMailClient(str(path))


def test_login_persists_the_session_and_derives_cookies(tmp_path, monkeypatch):
    """login() must leave a config that later runs can use without a password."""
    path = tmp_path / "fresh.json"
    path.write_text(json.dumps({"email": "a@proton.me", "password": "pw"}))
    client = ProtonMailClient(str(path))

    monkeypatch.setattr(client, "_srp_authenticate", lambda **kw: {
        "uid": "new-uid", "access_token": "new-access",
        "refresh_token": "new-refresh", "scope": "full", "key_salt": None,
    })
    monkeypatch.setattr(client, "setup", lambda: {
        "primary_key": True, "key_salt": True, "addresses": ["a@proton.me"],
    })

    result = client.login()
    assert result["uid"] == "new-uid"

    saved = json.loads(path.read_text())
    assert saved["uid"] == "new-uid"
    assert saved["auth_token"] == "new-access"
    # A REFRESH cookie is what lets refresh() rotate the token later.
    assert saved["cookies"]["AUTH-new-uid"] == "new-access"
    assert "REFRESH-new-uid" in saved["cookies"]
    # The live client must be using the new token immediately.
    assert client._http.headers["Authorization"] == "Bearer new-access"
    client.close()


def test_login_replaces_a_stale_session(tmp_path, monkeypatch):
    """Old AUTH/REFRESH cookies must not survive a re-login."""
    path = tmp_path / "stale.json"
    path.write_text(json.dumps({
        "email": "a@proton.me", "password": "pw",
        "uid": "old-uid", "auth_token": "old-access",
        "cookies": {"AUTH-old-uid": "old-access", "REFRESH-old-uid": "old-refresh"},
    }))
    client = ProtonMailClient(str(path))
    monkeypatch.setattr(client, "_srp_authenticate", lambda **kw: {
        "uid": "fresh-uid", "access_token": "fresh-access",
        "refresh_token": "fresh-refresh", "scope": "full", "key_salt": None,
    })
    monkeypatch.setattr(client, "setup", lambda: {
        "primary_key": True, "key_salt": True, "addresses": [],
    })

    client.login()
    cookies = json.loads(path.read_text())["cookies"]
    assert "AUTH-old-uid" not in cookies, "stale session cookie kept"
    assert "REFRESH-old-uid" not in cookies
    assert cookies["AUTH-fresh-uid"] == "fresh-access"
    client.close()


def test_srp_login_without_a_password_fails_before_any_request(client):
    client.password = ""
    with pytest.raises(RuntimeError, match="No password available"):
        client._srp_authenticate()


# ── CAPTCHA solver ──────────────────────────────────────────────────

cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")


def _puzzle_bg(hole_center, size=(370, 320)):
    """Mimic Proton's puzzle background: a dark hole with a white outline."""
    h, w = size
    img = np.zeros((h, w, 3), np.uint8)
    cv2.ellipse(img, (w // 2, h // 3), (120, 60), 20, 0, 360, (200, 230, 210), -1)
    img = cv2.GaussianBlur(img, (41, 41), 0)
    cx, cy = hole_center
    cv2.circle(img, (cx, cy), 26, (255, 255, 255), 3)
    cv2.circle(img, (cx, cy), 24, (8, 8, 8), -1)
    return cv2.imencode(".png", img)[1].tobytes()


@pytest.mark.parametrize("center", [(185, 120), (80, 60), (250, 175), (280, 230)])
def test_find_hole_locates_the_puzzle_gap(center):
    """A wrong coordinate means a failed login, so exactness matters."""
    from proton_mail_api.captcha import find_hole

    answer_x, answer_y = find_hole(_puzzle_bg(center))
    # answer = hole_center - (32, 82) with the background's y offset of 50
    assert abs(answer_x - (center[0] - 32)) <= 3
    assert abs(answer_y - (center[1] + 50 - 82)) <= 3


def test_find_hole_raises_instead_of_guessing_zero():
    """Returning (0,0) would silently submit a wrong answer."""
    from proton_mail_api.captcha import CaptchaError, find_hole

    flat = cv2.imencode(".png", np.full((200, 200, 3), 128, np.uint8))[1].tobytes()
    with pytest.raises(CaptchaError, match="not found"):
        find_hole(flat)


def test_find_hole_rejects_a_corrupt_image():
    from proton_mail_api.captcha import CaptchaError, find_hole

    with pytest.raises(CaptchaError, match="could not be decoded"):
        find_hole(b"not-an-image")


@pytest.mark.parametrize("answer_x,answer_y,expected", [
    (0, -50, (0, 0)),        # piece already at origin
    (100, 50, (50, 50)),
    (-40, -70, (-20, -10)),  # negative → left/up
])
def test_arrow_steps_matches_the_2px_key_step(answer_x, answer_y, expected):
    from proton_mail_api.captcha import arrow_steps

    assert arrow_steps(answer_x, answer_y) == expected


def test_solve_pow_answers_satisfy_the_hash_prefix():
    """Proton rejects the validate call unless every challenge is solved."""
    import hashlib

    from proton_mail_api.captcha import solve_pow

    challenges = ["abc", "def", "ghi"]
    n_zeros = 8
    answers = solve_pow(challenges, n_zeros)
    assert len(answers) == len(challenges)
    for challenge, answer in zip(challenges, answers, strict=True):
        digest = hashlib.sha256(f"{answer}{challenge}".encode()).hexdigest()
        n = (n_zeros + 3) // 4
        assert int(digest[:n], 16) < 2 ** (n * 4 - n_zeros)


def test_debug_dump_marks_the_detected_hole(tmp_path, monkeypatch):
    """Visible-mode debugging is the only way to see why a puzzle failed."""
    from proton_mail_api.captcha import PuzzleSolver, find_hole

    marked = tmp_path / "detected.png"
    monkeypatch.setattr(PuzzleSolver, "DEBUG_BG", str(tmp_path / "bg.png"))
    monkeypatch.setattr(PuzzleSolver, "DEBUG_MARKED", str(marked))

    solver = PuzzleSolver()
    solver.bg_bytes = _puzzle_bg((250, 175))
    solver._dump_debug(*find_hole(solver.bg_bytes))

    img = cv2.imread(str(marked))
    ys, xs = np.where((img[:, :, 2] > 180) & (img[:, :, 0] < 80) & (img[:, :, 1] < 80))
    assert abs(int(xs.mean()) - 250) <= 3, "marker not on the hole"
    assert abs(int(ys.mean()) - 175) <= 3


def test_login_falls_back_to_the_browser_on_human_verification(client, monkeypatch):
    """HV is not a wrong password — it is solvable, so login must not give up."""
    from proton_mail_api import HumanVerificationRequired

    def refuse(**kwargs):
        raise HumanVerificationRequired("captcha required", {"HumanVerification": 1})

    called = {}
    monkeypatch.setattr(client, "_srp_authenticate", refuse)
    monkeypatch.setattr(client, "_browser_login_with_captcha",
                        lambda **kw: called.update(kw) or True)
    monkeypatch.setattr(client, "setup", lambda: {
        "primary_key": True, "key_salt": True, "addresses": [],
    })

    result = client.login(headless=False, slow_mo=250)
    assert result["method"] == "captcha"
    # Debug options must reach the browser, not be silently dropped.
    assert called["headless"] is False
    assert called["slow_mo"] == 250


def test_login_can_refuse_the_browser_fallback(client, monkeypatch):
    """On a headless server, spawning a browser may be worse than failing."""
    from proton_mail_api import HumanVerificationRequired

    def refuse(**kwargs):
        raise HumanVerificationRequired("captcha required")

    monkeypatch.setattr(client, "_srp_authenticate", refuse)
    with pytest.raises(HumanVerificationRequired):
        client.login(allow_captcha=False)


def test_browser_refresh_cookie_is_not_double_wrapped(client):
    """The browser hands back an already-encoded JSON envelope.

    Wrapping it again produces a cookie refresh() cannot parse, which silently
    breaks every later token rotation.
    """
    from urllib.parse import quote, unquote

    envelope = quote(json.dumps({
        "ResponseType": "token", "ClientID": "WebMail",
        "GrantType": "refresh_token", "RefreshToken": "inner", "UID": "u1",
    }))
    client._store_session("u1", "access", envelope)
    stored = client.config["cookies"]["REFRESH-u1"]
    assert json.loads(unquote(stored))["RefreshToken"] == "inner"


def test_raw_refresh_token_gets_wrapped(client):
    """SRP returns a bare token, which refresh() expects to find wrapped."""
    from urllib.parse import unquote

    client._store_session("u2", "access", "bare-token")
    stored = client.config["cookies"]["REFRESH-u2"]
    assert json.loads(unquote(stored))["RefreshToken"] == "bare-token"


# -- SRP token extraction --------------------------------------------
#
# Proton's real /core/v4/auth success body has NO AccessToken field: it carries
# Code/UID/ServerProof/Scope only, and ships the tokens as Set-Cookie. Reading
# the body alone raises KeyError; trusting cookie *presence* is worse, because
# Proton also sets AUTH-<uid> on a REJECTED login.

_SRP_UID = "s4rjiwdgrtttwig3q7bxcs2cn3463pbr"


def _fake_srp(monkeypatch, *, server_proof=b"proof"):
    """Stub out proton.srp + gnupg so _srp_authenticate reaches the HTTP layer."""
    class FakeUser:
        def __init__(self, password, modulus):
            self.password = password

        def get_challenge(self):
            return b"eph"

        def process_challenge(self, salt, ephemeral, version):
            return b"proof"

        def verify_session(self, proof):
            self._ok = proof == server_proof

        def authenticated(self):
            return getattr(self, "_ok", False)

    class FakeGPG:
        def import_keys(self, key):
            return None

        def decrypt(self, data):
            # python-gnupg returns data even for a bad signature; the client
            # checks `valid`, so the stub must expose it.
            return types.SimpleNamespace(
                data=base64.b64encode(b"\x01" * 256),
                valid=True, status="signature valid", ok=True)

    srp_mod = types.ModuleType("proton.srp")
    srp_mod.User = FakeUser
    const_mod = types.ModuleType("proton.constants")
    const_mod.SRP_MODULUS_KEY = "key"
    proton_pkg = types.ModuleType("proton")
    proton_pkg.srp = srp_mod
    proton_pkg.constants = const_mod
    gnupg_mod = types.ModuleType("gnupg")
    gnupg_mod.GPG = FakeGPG

    monkeypatch.setitem(sys.modules, "proton", proton_pkg)
    monkeypatch.setitem(sys.modules, "proton.srp", srp_mod)
    monkeypatch.setitem(sys.modules, "proton.constants", const_mod)
    monkeypatch.setitem(sys.modules, "gnupg", gnupg_mod)


def _srp_transport(auth_body, auth_status=200, auth_cookies=()):
    """httpx transport replaying the SRP handshake."""
    import httpx

    def handler(request):
        if request.url.path.endswith("/auth/info"):
            return httpx.Response(200, json={
                "Modulus": "signed-modulus",
                "ServerEphemeral": base64.b64encode(b"B").decode(),
                "Salt": base64.b64encode(b"salt").decode(),
                "SRPSession": "sess",
                "Version": 4,
            })
        if request.url.path.endswith("/core/v4/auth"):
            return httpx.Response(
                auth_status, json=auth_body,
                headers=[("set-cookie", f"{name}={value}; Path=/")
                         for name, value in auth_cookies],
            )
        return httpx.Response(200, json={"Code": 1000})

    return httpx.MockTransport(handler)


@pytest.fixture
def srp_client(client, monkeypatch):
    _fake_srp(monkeypatch)
    return client


def _run_srp(srp_client, monkeypatch, transport):
    import httpx

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client",
        lambda **kw: real_client(**{**kw, "transport": transport}),
    )
    return srp_client._srp_authenticate()


_SUCCESS_BODY = {
    "Code": 1000,
    "UID": _SRP_UID,
    "ServerProof": base64.b64encode(b"proof").decode(),
    "Scope": "full mail",
    "TwoFactor": 0,
    "2FA": {"Enabled": 0},
}


def test_srp_reads_access_token_from_set_cookie(srp_client, monkeypatch):
    """The success body carries no AccessToken; the cookie is the only source."""
    result = _run_srp(srp_client, monkeypatch, _srp_transport(
        _SUCCESS_BODY,
        auth_cookies=[(f"AUTH-{_SRP_UID}", "cookie-access"),
                      (f"REFRESH-{_SRP_UID}", "cookie-refresh")],
    ))
    assert result["uid"] == _SRP_UID
    assert result["access_token"] == "cookie-access"
    assert result["refresh_token"] == "cookie-refresh"
    assert result["scope"] == "full mail"


def test_srp_rejects_a_session_with_no_token_anywhere(srp_client, monkeypatch):
    """Code 1000 with no AUTH cookie is not a usable session."""
    with pytest.raises(RuntimeError, match="no AccessToken"):
        _run_srp(srp_client, monkeypatch, _srp_transport(_SUCCESS_BODY))


def test_srp_ignores_a_foreign_uids_auth_cookie(srp_client, monkeypatch):
    """A stale cookie for another UID must not be adopted as this session."""
    with pytest.raises(RuntimeError, match="no AccessToken"):
        _run_srp(srp_client, monkeypatch, _srp_transport(
            _SUCCESS_BODY, auth_cookies=[("AUTH-someone-else", "not-mine")]))


def test_srp_rejects_a_non_1000_code_even_on_http_200(srp_client, monkeypatch):
    """Proton answers a bad password with 200 + Code 8002 in some flows."""
    with pytest.raises(RuntimeError, match="auth rejected"):
        _run_srp(srp_client, monkeypatch, _srp_transport({
            "Code": 8002,
            "Error": "Incorrect login credentials. Please try again.",
        }))


def test_srp_aborts_when_the_server_proof_is_wrong(srp_client, monkeypatch):
    """A forged server cannot hand us a session."""
    body = dict(_SUCCESS_BODY,
                ServerProof=base64.b64encode(b"forged").decode())
    with pytest.raises(RuntimeError, match="server proof mismatch"):
        _run_srp(srp_client, monkeypatch, _srp_transport(
            body, auth_cookies=[(f"AUTH-{_SRP_UID}", "cookie-access")]))


def test_srp_refuses_a_2fa_account(srp_client, monkeypatch):
    body = dict(_SUCCESS_BODY, TwoFactor=1, **{"2FA": {"Enabled": 1}})
    with pytest.raises(RuntimeError, match="2FA"):
        _run_srp(srp_client, monkeypatch, _srp_transport(
            body, auth_cookies=[(f"AUTH-{_SRP_UID}", "cookie-access")]))


def test_srp_maps_code_9001_to_human_verification(srp_client, monkeypatch):
    """HV is recoverable via the browser; a wrong password is not."""
    from proton_mail_api import HumanVerificationRequired

    with pytest.raises(HumanVerificationRequired):
        _run_srp(srp_client, monkeypatch, _srp_transport(
            {"Code": 9001, "Error": "Human verification required",
             "Details": {"HumanVerificationMethods": ["captcha"]}},
            auth_status=422,
        ))


# -- create_address ---------------------------------------------------
#
# Proton registers the new key server-side, but _decrypt_body only ever tries
# keys from config["address_keys"]. An alias missing from that map cannot have
# its mail decrypted until setup() is called again — so creation MUST persist
# the key it just generated.


def _stub_create_address(client, monkeypatch, *, keys_code=1000):
    """Stand in for the three network calls create_address makes."""
    calls = []

    def fake_api(path, method="GET", **kwargs):
        calls.append((method, path))
        if path == "/core/v4/addresses" and method == "POST":
            return {"Address": {"ID": "addr-id-1"}}
        if path == "/core/v4/keys/address" and method == "POST":
            return {"Code": keys_code}
        raise AssertionError(f"unexpected call {method} {path}")

    monkeypatch.setattr(client, "_api", fake_api)
    monkeypatch.setattr(client, "_generate_address_key", lambda email: {
        "private_key": f"PRIVKEY:{email}",
        "token": f"TOKEN:{email}",
        "signature": "sig",
        "signed_key_list": "skl",
        "fingerprint": "fp123",
    })
    return calls


def test_created_address_key_is_persisted_for_decrypt(client, monkeypatch):
    """Without this, mail sent to a fresh alias silently fails to decrypt."""
    _stub_create_address(client, monkeypatch)

    result = client.create_address("newalias")
    assert result["email"] == "newalias@proton.me"

    stored = client.config["address_keys"]["newalias@proton.me"]
    assert stored["private_key"] == "PRIVKEY:newalias@proton.me"
    assert stored["token"] == "TOKEN:newalias@proton.me"
    assert stored["address_id"] == "addr-id-1"

    # It must survive the process, not just live in memory.
    on_disk = json.loads(pathlib.Path(client.config_path).read_text())
    assert "newalias@proton.me" in on_disk["address_keys"]


def test_created_address_key_does_not_evict_existing_keys(client, monkeypatch):
    """Assigning a fresh dict would drop every other mailbox's key."""
    client.config["address_keys"] = {
        "old@proton.me": {"private_key": "OLD", "token": "OLDTOK"},
    }
    _stub_create_address(client, monkeypatch)

    client.create_address("second")

    assert set(client.config["address_keys"]) == {
        "old@proton.me", "second@proton.me"}
    assert client.config["address_keys"]["old@proton.me"]["private_key"] == "OLD"


def test_a_rejected_key_registration_stores_nothing(client, monkeypatch):
    """A half-created address must not leave an unusable key behind."""
    _stub_create_address(client, monkeypatch, keys_code=2001)

    with pytest.raises(RuntimeError, match="Key registration failed"):
        client.create_address("doomed")

    assert "doomed@proton.me" not in client.config.get("address_keys", {})


# -- disable / enable / delete ----------------------------------------
#
# Proton allows exactly ONE address deletion per year. Past that quota every
# delete is refused with Code 2011 — so the disable that delete_address performs
# first would otherwise leave the address permanently switched off.


def _addr_calls(client, monkeypatch, *, delete_error=None):
    """Record API calls; optionally make DELETE fail like a spent quota."""
    calls = []

    def fake_api(path, method="GET", **kwargs):
        calls.append((method, path))
        if method == "DELETE" and delete_error:
            raise RuntimeError(delete_error)
        return {"Code": 1000}

    monkeypatch.setattr(client, "_api", fake_api)
    return calls


def test_delete_disables_first_because_proton_refuses_enabled_addresses(
        client, monkeypatch):
    """409 Code 2502: 'Address is enabled. Please disable it before deleting'."""
    calls = _addr_calls(client, monkeypatch)

    client.delete_address("addr-1")

    assert calls == [
        ("PUT", "/core/v4/addresses/addr-1/disable"),
        ("DELETE", "/core/v4/addresses/addr-1"),
    ]


def test_a_refused_delete_re_enables_the_address(client, monkeypatch):
    """Only one delete per year is allowed; the rest must not disable anything."""
    calls = _addr_calls(client, monkeypatch, delete_error=(
        "API /core/v4/addresses/addr-1: 422 — "
        '{"Code":2011,"Error":"You can only delete one address per year"}'
    ))

    with pytest.raises(RuntimeError, match="one address per year"):
        client.delete_address("addr-1")

    assert calls[-1] == ("PUT", "/core/v4/addresses/addr-1/enable"), \
        "a refused delete left the address disabled"


def test_a_refused_delete_keeps_the_local_key(client, monkeypatch):
    """The address still exists, so its key must stay usable."""
    client.config["address_keys"] = {
        "keep@proton.me": {"address_id": "addr-1", "private_key": "K"},
    }
    _addr_calls(client, monkeypatch, delete_error="API x: 422 — nope")

    with pytest.raises(RuntimeError):
        client.delete_address("addr-1", email="keep@proton.me")

    assert "keep@proton.me" in client.config["address_keys"]


def test_a_successful_delete_drops_the_local_key(client, monkeypatch):
    """A dead key would be retried against every incoming message."""
    client.config["address_keys"] = {
        "gone@proton.me": {"address_id": "addr-1", "private_key": "K"},
        "stays@proton.me": {"address_id": "addr-2", "private_key": "K2"},
    }
    _addr_calls(client, monkeypatch)

    client.delete_address("addr-1")

    assert set(client.config["address_keys"]) == {"stays@proton.me"}


@pytest.mark.parametrize("action", ["disable_address", "enable_address"])
def test_a_status_change_drops_the_address_cache(client, monkeypatch, action):
    """addresses() caches for 5 minutes; a stale status misleads the caller."""
    _addr_calls(client, monkeypatch)
    client._addr_cache = [{"email": "stale@proton.me", "status": 1}]
    client._addr_cache_time = time.time()

    getattr(client, action)("addr-1")

    assert client._addr_cache is None, "stale address status survived"
