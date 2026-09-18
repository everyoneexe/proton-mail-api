"""
proton-mail-api — Proton Mail HTTP API client with PGP decrypt.

Usage (import):
    from proton_mail_api import ProtonMailClient
    client = ProtonMailClient("/path/to/account.json")
    msgs = client.inbox(size=10)
    body = client.read(msgs["messages"][0]["id"])
    code = client.wait_code(to_filter="myaddr@proton.me", from_filter="github")

Usage (CLI):
    proton-mail --config account.json inbox
    proton-mail --config account.json read <msg_id>
    proton-mail --config account.json code --from github --timeout 120

Requires: Node.js >= 18 (for PGP decrypt via openpgp.js)
"""
import base64
import json
import logging
import os
import re
import stat
import tempfile
import threading
import time
from html import unescape
from urllib.parse import unquote

import bcrypt
import httpx

log = logging.getLogger(__name__)

APP_VERSION = "web-mail@5.0.121.4"
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# API error code Proton returns when it wants human verification.
HV_REQUIRED_CODE = 9001


class HumanVerificationRequired(RuntimeError):
    """Proton wants CAPTCHA/human verification for login.

    Kept separate from a wrong password: the caller can fall back to a
    browser and solve the puzzle, but retrying a wrong password is pointless.
    """

    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or {}


class ProtonReader:
    """Proton Mail API client with PGP decrypt support.

    Reads emails, decrypts PGP-encrypted bodies, manages aliases,
    and waits for verification codes — all via HTTP API + Node.js openpgp.

    Args:
        config_path: Path to account config JSON file.

    Example:
        >>> client = ProtonReader("my_account.json")
        >>> msgs = client.inbox(size=5)
        >>> body = client.read(msgs["messages"][0]["id"])
        >>> code = client.wait_code(to_filter="me@proton.me", from_filter="github")
    """

    def __init__(self, config_path):
        """Initialize with a config JSON file path.

        Args:
            config_path: Path to account config JSON file.
                         Relative paths are resolved from current working directory.
        """
        if not os.path.isabs(config_path):
            config_path = os.path.join(os.getcwd(), config_path)
        self.config_path = config_path
        self._load_config()
        # reentrant: avoid deadlock in the _api -> refresh -> _api chain
        self._refresh_lock = threading.RLock()
        self._last_refresh_time = 0
        self._last_browser_login_time = 0
        # Address list cache — Proton /addresses page 1 takes ~9s, and
        # addresses rarely change
        self._addr_cache = None
        self._addr_cache_time = 0
        self._addr_cache_ttl = 300  # 5 min
        # Single httpx.Client — opening a new Client per request leaks sockets.
        # Headers/cookies are refreshed via _sync_client_auth() when the token
        # is renewed.
        self._http = httpx.Client(
            base_url="https://mail.proton.me/api",
            follow_redirects=False,
            timeout=30,
        )
        self._sync_client_auth()

    def close(self):
        """Close HTTP connections."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _load_config(self):
        """Load the config.

        uid/auth_token are NOT REQUIRED: a config with only email+password is
        valid, and the session is opened through SRP via login().
        """
        with open(self.config_path) as f:
            self.config = json.load(f)
        self.uid = self.config.get("uid", "")
        self.auth_token = self.config.get("auth_token", "")
        self.email = self.config.get("email", "")
        self.password = self.config.get("password", "")
        self.key_salt = self.config.get("key_salt", "")
        if not (self.uid and self.auth_token) and not (self.email and self.password):
            raise ValueError(
                f"{self.config_path}: either uid+auth_token (existing session) or "
                "email+password (SRP login) is required"
            )

    def _save_config(self):
        """Write the config atomically with 0600 permissions.

        Writing straight with open(path, "w") truncates the file first; if a
        second process/thread refreshing the same config slips in between, the
        password, tokens and all PGP private keys are lost permanently. That is
        why a temp file is written in the same directory and swapped in
        atomically with os.replace.
        """
        directory = os.path.dirname(self.config_path) or "."
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=".proton-config-", suffix=".tmp"
        )
        try:
            # 0600 — do not expose secrets to the world
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.config_path)
        except BaseException:
            os.unlink(tmp_path)
            raise

    def _headers(self):
        return {
            "User-Agent": UA,
            "x-pm-appversion": APP_VERSION,
            "x-pm-uid": self.uid,
            "Authorization": f"Bearer {self.auth_token}",
            "accept": "application/vnd.protonmail.v1+json",
        }

    def _cookie_jar(self):
        cookies = {}
        for name, val in self.config.get("cookies", {}).items():
            if isinstance(val, str):
                cookies[name] = val
            elif isinstance(val, dict):
                cookies[name] = val.get("value", "")
        return cookies

    def _sync_client_auth(self):
        """Align the shared client's headers/cookies with the config."""
        self._http.headers.update(self._headers())
        self._http.cookies.clear()
        for name, val in self._cookie_jar().items():
            self._http.cookies.set(name, val)

    # Scopes that come from the account's plan. These are missing not because
    # the session is locked but because the plan never includes that feature;
    # logging in again will not grant them. (On a free account "organization"
    # for aliases behaves exactly like this.)
    _PLAN_SCOPES = frozenset({
        "organization", "vpn", "drive", "pass", "wallet", "docs", "meet",
    })

    def _api(self, path, method="GET", _retry=0, **kwargs):
        """Make an API request. Handles 401/403/429/5xx automatically."""
        try:
            r = self._http.request(method.upper(), path, **kwargs)
        except httpx.HTTPError:
            # Connection error — retry
            if _retry < 2:
                time.sleep(2)
                return self._api(path, method=method, _retry=_retry + 1, **kwargs)
            raise

        # 401 — token expired -> try refresh
        if r.status_code == 401 and _retry < 2:
            now = time.time()
            with self._refresh_lock:
                # Skip retrying if a refresh happened within 60s — the new
                # token is already in place
                if now - self._last_refresh_time < 60:
                    log.debug("Token recently refreshed (cooldown); retrying request")
                    self._sync_client_auth()
                else:
                    self._last_refresh_time = now
                    log.info("Auth token expired; refreshing")
                    try:
                        self.refresh()
                    except (RuntimeError, OSError, ValueError, httpx.HTTPError) as e:
                        # If the REFRESH token is broken too, fall back to a
                        # browser login (with cooldown)
                        log.warning("Token refresh failed (%s); trying browser login", e)
                        self._browser_relogin()
            return self._api(path, method=method, _retry=_retry + 1, **kwargs)

        # 403 — insufficient scope. There are two distinct causes and only one
        # of them is fixed by logging in:
        #   * the session is locked/restricted (scope: locked) -> a fresh login
        #     helps;
        #   * the requested scope is absent from the account's PLAN (e.g.
        #     organization is never granted on a free account) -> logging in
        #     again returns the same 403, and opening a browser is pure waste.
        if r.status_code == 403 and _retry < 1:
            err_text = r.text
            if "scope" in err_text.lower() or "MissingScopes" in err_text:
                missing = set()
                try:
                    missing = set(
                        r.json().get("Details", {}).get("MissingScopes") or []
                    )
                except ValueError:
                    pass
                if missing & self._PLAN_SCOPES:
                    log.warning(
                        "Missing plan-level scope %s for %s; the account's plan "
                        "does not grant it, so re-login cannot help",
                        sorted(missing & self._PLAN_SCOPES), path,
                    )
                else:
                    log.info("Insufficient scope; attempting browser login")
                    # Retrying is pointless if the cooldown blocks it — the
                    # same 403 comes back.
                    if self._browser_relogin():
                        return self._api(path, method=method,
                                         _retry=_retry + 1, **kwargs)

        # 429 — rate limited -> wait and retry. When no retries are left the
        # error is raised without waiting; sleeping for nothing would block the
        # caller needlessly.
        if r.status_code == 429 and _retry < 3:
            try:
                retry_after = int(r.headers.get("Retry-After", "10"))
            except ValueError:
                retry_after = 10
            retry_after = max(0, min(retry_after, 60))
            log.warning("Rate limited; waiting %ss", retry_after)
            time.sleep(retry_after)
            return self._api(path, method=method, _retry=_retry + 1, **kwargs)

        # 5xx — server error -> retry
        if r.status_code >= 500 and _retry < 2:
            time.sleep(3)
            return self._api(path, method=method, _retry=_retry + 1, **kwargs)

        if r.status_code != 200:
            raise RuntimeError(f"API {path}: {r.status_code} — {r.text[:200]}")
        return r.json()

    def _browser_login_with_captcha(self, timeout=180, headless=None,
                                    slow_mo=0, keep_open=0):
        """Log in through a browser, auto-solve the puzzle CAPTCHA, grab the
        session.

        Used when the SRP HTTP path asks for human verification. The CAPTCHA
        must be solved inside a browser: the verification request carries
        coordinates computed on the canvas plus the `pcaptcha` header.

        Requires: pip install proton-mail-api[captcha]

        Args:
            headless: When None, the PROTON_HEADLESS environment variable is
                      used ("0" -> visible). Visible mode is for debugging:
                      where the puzzle blows up can only be seen by watching.
            slow_mo: Milliseconds to wait after every Playwright action. In
                     visible mode 250-500 makes it easier to follow.
            keep_open: Seconds to wait before closing the browser on failure.
                       For inspecting the last screen in visible mode.
        """
        import asyncio

        try:
            from playwright.async_api import (
                Error as PlaywrightError,
            )
            from playwright.async_api import (
                async_playwright,
            )
        except ImportError:
            raise ImportError(
                "playwright is required to solve the login CAPTCHA. "
                "Install with: pip install proton-mail-api[captcha] "
                "&& playwright install chromium"
            )
        from .captcha import CaptchaError, PuzzleSolver

        if headless is None:
            headless = os.environ.get("PROTON_HEADLESS", "1") != "0"
        username = self.email.split("@")[0]
        log.info("Launching browser (headless=%s) for CAPTCHA login", headless)

        async def _run():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=headless,
                                                  slow_mo=slow_mo)
                page = None
                try:
                    ctx = await browser.new_context(user_agent=UA)
                    page = await ctx.new_page()
                    # Do not silently swallow in-browser errors — why the
                    # puzzle broke is usually visible here.
                    page.on("console", lambda m: log.debug("browser console [%s]: %s",
                                                           m.type, m.text))
                    page.on("pageerror", lambda e: log.warning("browser error: %s", e))

                    solver = PuzzleSolver()
                    # Listeners must be installed BEFORE goto: the init/bg
                    # responses go by while the page is loading.
                    await solver.attach(page)

                    # The real verdict for the login is the /core/v4/auth
                    # response. Proton writes an AUTH-<uid> cookie even for a
                    # WRONG password (pre-auth session), so the presence of the
                    # cookie is NOT proof of success: look for Code 1000.
                    verdict = {}

                    async def on_auth(resp):
                        if not resp.url.rstrip("/").endswith("/core/v4/auth"):
                            return
                        try:
                            body = await resp.json()
                        except (ValueError, PlaywrightError):
                            # The body is not JSON, or the response can no
                            # longer be read (the page is gone). Move on
                            # without corrupting the verdict.
                            return
                        if isinstance(body, dict) and "Code" in body:
                            verdict.clear()
                            verdict.update(body)

                    page.on("response", on_auth)

                    await page.goto("https://account.proton.me/login",
                                    timeout=60_000)
                    # Proton Account is an SPA: even after goto returns, the
                    # screen may still show "Loading Proton Account.." and the
                    # form is absent from the DOM. Wait for the field itself
                    # instead of a fixed sleep.
                    await page.wait_for_selector('input[id="username"]',
                                                 timeout=60_000)
                    await page.fill('input[id="username"]', username)
                    await page.fill('input[id="password"]', self.password)
                    await page.locator('button[type="submit"]').click()

                    # A single wait loop: the verdict, the CAPTCHA and 2FA are
                    # watched at the same time and whichever arrives first is
                    # acted on. The CAPTCHA does not always appear, so waiting
                    # for it separately would be wrong.
                    uid = access = refresh = None
                    captcha_done = False

                    def read_tokens(jar, want_uid):
                        """Bind the tokens to the verified UID, not to any
                        arbitrary AUTH- cookie."""
                        a = r = None
                        for c in jar:
                            name, value = c.get("name", ""), c.get("value", "")
                            if name == f"AUTH-{want_uid}":
                                a = value
                            elif name == f"REFRESH-{want_uid}":
                                r = value
                        return a, r

                    for _ in range(timeout):
                        await page.wait_for_timeout(1000)

                        code = verdict.get("Code")
                        if code == 1000:
                            if (verdict.get("2FA", {}).get("Enabled")
                                    or verdict.get("TwoFactor")):
                                raise RuntimeError(
                                    "Account has 2FA enabled; automated login "
                                    "cannot complete without the TOTP code"
                                )
                            uid = verdict["UID"]
                            access, refresh = read_tokens(
                                await ctx.cookies(), uid)
                            if access:
                                break
                            continue
                        if code is not None and code != HV_REQUIRED_CODE:
                            raise RuntimeError(
                                "login rejected by Proton: "
                                f"{verdict.get('Error') or verdict}"
                            )

                        # If a CAPTCHA showed up, solve it; after solving,
                        # Proton issues a new /auth request, so drop the old
                        # verdict.
                        if not captcha_done and await solver.has_iframe(page):
                            log.info("CAPTCHA appeared; solving")
                            await solver.solve_now(page)
                            captcha_done = True
                            verdict.clear()
                            continue

                        # Once the 2FA screen appears there is no point waiting.
                        if await page.locator(
                            'input[id="twoFa"], input[name="totp"]'
                        ).count():
                            raise RuntimeError(
                                "Account has 2FA enabled; automated login cannot "
                                "complete without the TOTP code"
                            )

                    if not (uid and access):
                        raise RuntimeError(
                            f"Login did not complete within {timeout}s "
                            f"(last URL: {page.url}, "
                            f"auth_code={verdict.get('Code')}, "
                            f"captcha_solved={captcha_done})"
                        )
                    log.info("Session established (captcha_solved=%s, scope=%s)",
                             captcha_done, verdict.get("Scope", "")[:40])
                    return uid, access, refresh
                except Exception as e:
                    # Diagnostics: screenshot + last URL. Enrich the error
                    # without swallowing it.
                    if page is not None:
                        shot = "/tmp/proton-login-failed.png"
                        try:
                            await page.screenshot(path=shot, full_page=True)
                            log.error("Login failed at %s — screenshot: %s",
                                      page.url, shot)
                        except Exception as shot_err:  # noqa: BLE001
                            log.debug("screenshot failed: %s", shot_err)
                        if keep_open:
                            log.warning("Keeping browser open for %ss "
                                        "(inspect the window)", keep_open)
                            await page.wait_for_timeout(keep_open * 1000)
                    if isinstance(e, CaptchaError):
                        raise CaptchaError(
                            f"{e} (screenshot: /tmp/proton-login-failed.png)"
                        ) from e
                    raise
                finally:
                    await browser.close()

        uid, access, refresh = asyncio.run(_run())
        self._last_browser_login_time = time.time()
        self._store_session(uid, access, refresh)
        log.info("CAPTCHA login succeeded for %s", self.email)
        return True

    _BROWSER_LOGIN_COOLDOWN = 120  # seconds

    def _browser_relogin(self):
        """Log in through a browser and get fresh tokens (with all scopes).

        The cooldown is enforced here: every call starts a new headless
        Chromium, and the 401/403 ladder can fall through to this point on
        every request. If the cooldown were left to the call site, a single
        unauthorized token would open one browser per request.

        Returns:
            bool: True if a login was attempted, False if it was skipped
                  because of the cooldown.
        """
        with self._refresh_lock:
            now = time.time()
            since = now - self._last_browser_login_time
            if since < self._BROWSER_LOGIN_COOLDOWN:
                log.warning(
                    "Browser login in cooldown (%ds left); skipping",
                    int(self._BROWSER_LOGIN_COOLDOWN - since),
                )
                return False
            self._last_browser_login_time = now
            import asyncio
            try:
                from playwright.async_api import (
                    Error as PlaywrightError,
                )
                from playwright.async_api import async_playwright
            except ImportError:
                raise ImportError(
                    "playwright is required for browser relogin. "
                    "Install with: pip install proton-mail-api[browser]"
                )

            username = self.email.split("@")[0]

            async def _login():
                """Return (uid, scope, cookies) on success; raise otherwise.

                Nothing is written to the config here: a failed relogin must
                not clobber a session that still works.
                """
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    try:
                        ctx = await browser.new_context(user_agent=UA)
                        page = await ctx.new_page()

                        # Proton sets AUTH-<uid> even for a REJECTED login, so
                        # the cookie jar cannot tell us whether this worked.
                        # /core/v4/auth's Code is the only reliable verdict.
                        verdict = {}

                        async def on_auth(resp):
                            if not resp.url.rstrip("/").endswith("/core/v4/auth"):
                                return
                            try:
                                body = await resp.json()
                            except (ValueError, PlaywrightError):
                                return
                            if isinstance(body, dict) and "Code" in body:
                                verdict.clear()
                                verdict.update(body)

                        page.on("response", on_auth)

                        await page.goto("https://account.proton.me/login",
                                        timeout=60_000)
                        # SPA: a fixed sleep misses the form on a slow link.
                        await page.wait_for_selector('input[id="username"]',
                                                     timeout=60_000)
                        await page.fill('input[id="username"]', username)
                        await page.fill('input[id="password"]', self.password)
                        await page.locator('button[type="submit"]').click()

                        uid = None
                        for _ in range(30):
                            await page.wait_for_timeout(1000)
                            code = verdict.get("Code")
                            if code == 1000:
                                uid = verdict["UID"]
                                break
                            if code is not None:
                                raise RuntimeError(
                                    "browser relogin rejected by Proton: "
                                    f"{verdict.get('Error') or verdict}"
                                )
                        if uid is None:
                            raise RuntimeError(
                                "browser relogin did not complete "
                                f"(last URL: {page.url})"
                            )

                        jar = {c.get("name", ""): c.get("value", "")
                               for c in await ctx.cookies()}
                        if f"AUTH-{uid}" not in jar:
                            raise RuntimeError(
                                "browser relogin produced no token for the "
                                f"authenticated UID (cookies={sorted(jar)})"
                            )
                        keep = {f"AUTH-{uid}", f"REFRESH-{uid}",
                                "Session-Id", "Domain", "Tag", "iaas",
                                "Features"}
                        return (uid, verdict.get("Scope", ""),
                                {n: v for n, v in jar.items() if n in keep})
                    finally:
                        await browser.close()

            uid, scope, cookies = asyncio.run(_login())
            self.uid = uid
            self.auth_token = cookies[f"AUTH-{uid}"]
            self.config["uid"] = uid
            self.config["auth_token"] = self.auth_token
            self.config["cookies"] = cookies
            self._save_config()
            self._sync_client_auth()
            log.info("Browser relogin succeeded for %s (scope=%s)",
                     self.email, scope[:60])
            return True

    # ── Token refresh ────────────────────────────────────────────────

    def refresh(self):
        """Get a new AUTH token with the REFRESH cookie. Guarded by a lock.

        Note: Proton's WebAccount/WebMail refresh returns the new tokens in the
        Set-Cookie header, NOT in the JSON body (AUTH-<uid>, REFRESH-<uid>,
        Session-Id, Tag). The UID changes as well (RefreshCounter increments).
        """
        with self._refresh_lock:
            # Find the REFRESH cookie
            cookies = self.config.get("cookies", {})

            refresh_payload = None
            for name, val in cookies.items():
                if not name.startswith("REFRESH-"):
                    continue
                raw = val if isinstance(val, str) else val.get("value", "")
                try:
                    refresh_payload = json.loads(unquote(raw))
                except (ValueError, TypeError):
                    # The cookie carries the raw refresh token (not
                    # URL-encoded JSON)
                    refresh_payload = {
                        "ResponseType": "token",
                        "ClientID": "WebMail",
                        "GrantType": "refresh_token",
                        "RefreshToken": raw,
                        "UID": name[len("REFRESH-"):],
                    }
                break

            if not refresh_payload:
                raise RuntimeError(
                    "REFRESH cookie not found. Add the REFRESH-{uid} cookie "
                    "to the config."
                )

            # Pick the appversion matching the ClientID
            # (WebAccount -> web-account, otherwise WebMail)
            client_id = refresh_payload.get("ClientID", "WebMail")
            if client_id == "WebAccount":
                refresh_appversion = "web-account@5.0.999.0"
            else:
                refresh_appversion = APP_VERSION

            # Send the session cookies too (the refresh endpoint wants
            # Session-Id)
            refresh_cookies = {}
            for name, val in self.config.get("cookies", {}).items():
                if isinstance(val, str):
                    refresh_cookies[name] = val
                elif isinstance(val, dict):
                    refresh_cookies[name] = val.get("value", "")

            r = httpx.post(
                "https://mail.proton.me/api/auth/v4/refresh",
                headers={
                    "User-Agent": UA,
                    "x-pm-appversion": refresh_appversion,
                    "x-pm-uid": self.uid,
                    "Content-Type": "application/json",
                },
                cookies=refresh_cookies,
                json=refresh_payload,
                timeout=15,
            )

            data = r.json()
            if r.status_code != 200 or data.get("Code") != 1000:
                raise RuntimeError(f"Token refresh failed: {data}")

            # Pull the new tokens out of the Set-Cookie header
            new_uid = data.get("UID", self.uid)
            resp_cookies = {c.name: c.value for c in r.cookies.jar}

            # some clients also put it in the body
            new_access = data.get("AccessToken")
            new_refresh = data.get("RefreshToken")

            for cname, cval in resp_cookies.items():
                if cname.startswith("AUTH-"):
                    new_access = cval
                    new_uid = cname[len("AUTH-"):]
                elif cname.startswith("REFRESH-"):
                    # REFRESH cookie value = URL-encoded JSON; extract
                    # RefreshToken from it
                    try:
                        rj = json.loads(unquote(cval or ""))
                        new_refresh = rj.get("RefreshToken", new_refresh)
                    except (ValueError, TypeError):
                        # Raw refresh token — no JSON envelope
                        new_refresh = cval

            if not new_access:
                raise RuntimeError(
                    f"Token refresh: new AUTH token not found "
                    f"(cookies={list(resp_cookies.keys())})"
                )

            # Update auth_token
            self.auth_token = new_access
            self.config["auth_token"] = new_access
            auth_key = f"AUTH-{new_uid}"

            # Drop the old AUTH/REFRESH cookies, write the new ones
            from urllib.parse import quote
            cfg_cookies = self.config.setdefault("cookies", {})
            for old_key in [k for k in cfg_cookies
                            if k.startswith(("AUTH-", "REFRESH-"))]:
                del cfg_cookies[old_key]

            cfg_cookies[auth_key] = new_access
            if new_refresh:
                new_refresh_val = json.dumps({
                    "ResponseType": "token",
                    "ClientID": client_id,
                    "GrantType": "refresh_token",
                    "RefreshToken": new_refresh,
                    "UID": new_uid,
                })
                cfg_cookies[f"REFRESH-{new_uid}"] = quote(new_refresh_val)

            # Update Session-Id / Tag (when present)
            for cname in ("Session-Id", "Tag"):
                if cname in resp_cookies:
                    cfg_cookies[cname] = resp_cookies[cname]

            if "all_auth_cookies" in self.config:
                self.config["all_auth_cookies"] = {new_uid: new_access}

            self.uid = new_uid
            self.config["uid"] = new_uid
            self._last_refresh_time = time.time()
            self._save_config()
            self._sync_client_auth()
            log.info("Auth token refreshed for %s", self.email)
            return True

    # ── Setup: fetch key info from API ───────────────────────────────

    def setup(self):
        """Fetch PrimaryKey and address keys from the API and write them to the
        config.

        KeySalt needs the keys/salts endpoint — on a 403 the key_salt has to be
        entered by hand, or it is fetched through an SRP login."""

        # 1. User -> PrimaryKey
        user_data = self._api("/core/v4/users")
        user = user_data["User"]
        user_keys = user.get("Keys", [])
        primary_key = user_keys[0]["PrivateKey"] if user_keys else None

        if primary_key:
            self.config["primary_key"] = primary_key

        # 2. Try KeySalt (may 403 — scope: locked)
        try:
            salts_data = self._api("/core/v4/keys/salts")
            key_salt = salts_data.get("KeySalts", [{}])[0].get("KeySalt")
            if key_salt:
                self.config["key_salt"] = key_salt
                self.key_salt = key_salt
                log.info("KeySalt fetched from keys/salts")
        except (RuntimeError, httpx.HTTPError) as e:
            log.warning("KeySalt fetch failed (scope:locked?): %s; trying SRP login", e)
            # Try fetching the KeySalt through an SRP login
            try:
                key_salt = self._srp_get_key_salt()
                if key_salt:
                    self.config["key_salt"] = key_salt
                    self.key_salt = key_salt
                    log.info("KeySalt fetched via SRP login")
            except (RuntimeError, ImportError, KeyError, httpx.HTTPError) as e2:
                log.warning("SRP KeySalt fetch failed: %s", e2)

        # 3. Addresses -> address keys (all pages)
        addr_keys = {}
        for addr in self._fetch_addresses_raw(with_keys=True):
            email = addr["Email"]
            keys = addr.get("Keys", [])
            if keys:
                k = keys[0]
                addr_keys[email] = {
                    "address_id": addr["ID"],
                    "private_key": k["PrivateKey"],
                    "token": k.get("Token"),
                    "fingerprint": k.get("Fingerprint"),
                }
        self.config["address_keys"] = addr_keys

        self._save_config()
        log.info("Key material updated for %d addresses", len(addr_keys))
        return {
            "primary_key": bool(primary_key),
            "key_salt": bool(self.config.get("key_salt")),
            "addresses": list(addr_keys.keys()),
        }

    def login(self, allow_captcha=True, headless=None, slow_mo=0, keep_open=0):
        """Log in with email + password and write the session to the config.

        Plain HTTP SRP is tried first (fast, no browser needed). If Proton asks
        for human verification (HV / 9001), the flow falls back to a browser and
        the puzzle CAPTCHA is solved automatically.

        Requires: pip install proton-mail-api[srp]
                  for the CAPTCHA fallback also: proton-mail-api[captcha]

        Args:
            allow_captcha: When False, no browser fallback happens if a CAPTCHA
                           is requested; an error is raised instead. For
                           deliberate use on a headless server.
            headless: Whether the CAPTCHA browser runs hidden. None -> the
                      PROTON_HEADLESS environment variable ("0" -> visible).
            slow_mo: Per-action delay in ms in visible mode (for watching).
            keep_open: How long to keep the browser open on failure (seconds).

        Returns:
            dict: {"uid", "email", "addresses", "key_salt": bool, "method"}
        """
        method = "srp"
        try:
            auth = self._srp_authenticate()
        except HumanVerificationRequired:
            if not allow_captcha:
                raise
            log.info("Proton requires human verification; solving CAPTCHA in browser")
            self._browser_login_with_captcha(
                headless=headless, slow_mo=slow_mo, keep_open=keep_open
            )
            method = "captcha"
        else:
            self._store_session(
                auth["uid"], auth["access_token"], auth.get("refresh_token")
            )
            log.info("SRP login succeeded for %s", self.email)

        result = self.setup()
        return {
            "uid": self.uid,
            "email": self.email,
            "key_salt": result["key_salt"],
            "addresses": result["addresses"],
            "method": method,
        }

    def _store_session(self, uid, access_token, refresh_token=None):
        """Write the new session to the config and align the live client."""
        self.uid = uid
        self.auth_token = access_token
        self.config["uid"] = uid
        self.config["auth_token"] = access_token

        cookies = self.config.setdefault("cookies", {})
        for old in [k for k in cookies if k.startswith(("AUTH-", "REFRESH-"))]:
            del cookies[old]
        cookies[f"AUTH-{uid}"] = access_token
        if refresh_token:
            from urllib.parse import quote, unquote
            # SRP hands back a raw RefreshToken; the browser cookie, on the
            # other hand, already carries a URL-encoded JSON envelope. Wrapping
            # it a second time breaks refresh().
            try:
                json.loads(unquote(refresh_token))
                wrapped = refresh_token
            except ValueError:
                wrapped = quote(json.dumps({
                    "ResponseType": "token",
                    "ClientID": "WebMail",
                    "GrantType": "refresh_token",
                    "RefreshToken": refresh_token,
                    "UID": uid,
                }))
            cookies[f"REFRESH-{uid}"] = wrapped

        self._save_config()
        self._sync_client_auth()

    def _srp_get_key_salt(self):
        """Fetch the KeySalt via an SRP login — for when keys/salts 403s."""
        return self._srp_authenticate(fetch_key_salt=True)["key_salt"]

    def _srp_authenticate(self, fetch_key_salt=False):
        """Run the Proton SRP flow.

        Requires: pip install proton-mail-api[srp]

        Args:
            fetch_key_salt: When True the KeySalt is fetched as well and the
                            session is closed. When False the session is left
                            OPEN (login() relies on this).
        """
        if not self.password:
            raise RuntimeError("No password available; cannot perform SRP login")

        # An SRP login is needed — validate the dependencies BEFORE any
        # network request
        try:
            import gnupg
            from proton.constants import SRP_MODULUS_KEY
            from proton.srp import User as SRPUser
        except ImportError:
            raise ImportError(
                "proton-client and python-gnupg are required for SRP login. "
                "Install with: pip install proton-mail-api[srp]"
            )

        username = self.email.split("@")[0]

        with httpx.Client(
            headers={"User-Agent": UA, "x-pm-appversion": APP_VERSION},
            base_url="https://mail.proton.me/api",
            # do not leak the Authorization header to a redirect target
            follow_redirects=False,
            timeout=30,
        ) as client:
            # 1. Auth info — salt, server challenge, modulus
            info_resp = client.post("/core/v4/auth/info", json={"Username": username})
            if info_resp.status_code != 200:
                raise RuntimeError(f"auth/info: {info_resp.status_code}")
            info = info_resp.json()

            # 2. VERIFY the modulus signature — decrypting alone is not enough.
            # The modulus is SRP's group parameter. If the server (or someone
            # in the middle) hands over an unsigned modulus, the password proof
            # is derived against a group of their choosing and SRP's guarantee
            # collapses. python-gnupg returns the data even when the signature
            # is invalid, so the `valid` flag must be checked explicitly.
            gpg = gnupg.GPG()
            gpg.import_keys(SRP_MODULUS_KEY)
            verified = gpg.decrypt(info["Modulus"])
            if not getattr(verified, "valid", False):
                raise RuntimeError(
                    "SRP modulus signature is not valid "
                    f"(status={getattr(verified, 'status', None)!r}) — refusing to "
                    "derive a password proof against an unverified group"
                )
            modulus = base64.b64decode(verified.data.strip())

            # 3. Client proof. process_challenge returns the client proof (M);
            # the ephemeral (A) comes from get_challenge().
            srp_user = SRPUser(self.password, modulus)
            client_ephemeral = srp_user.get_challenge()
            client_proof = srp_user.process_challenge(
                base64.b64decode(info["Salt"]),
                base64.b64decode(info["ServerEphemeral"]),
                info.get("Version", 4),
            )
            if client_proof is None:
                raise RuntimeError("SRP-6a safety check failed (bad server ephemeral)")

            # 4. Auth
            auth_resp = client.post("/core/v4/auth", json={
                "Username": username,
                "ClientProof": base64.b64encode(client_proof).decode(),
                "ClientEphemeral": base64.b64encode(client_ephemeral).decode(),
                "SRPSession": info["SRPSession"],
            })
            if auth_resp.status_code != 200:
                # HV arrives as 422 + Code 9001. It must be distinguished from
                # a wrong password: one can be cleared with a browser, the
                # other cannot.
                try:
                    err = auth_resp.json()
                except ValueError:
                    err = {}
                if err.get("Code") == HV_REQUIRED_CODE:
                    raise HumanVerificationRequired(
                        "Proton requires human verification (CAPTCHA) for this login",
                        err.get("Details"),
                    )
                raise RuntimeError(
                    f"auth: {auth_resp.status_code} — {auth_resp.text[:200]}"
                )
            auth_data = auth_resp.json()
            if auth_data.get("Code") != 1000:
                raise RuntimeError(f"auth rejected: {auth_data}")

            # 5. Verify the server's proof — it proves the other side really
            # knows the password. Skipping it would let a fake server hand out
            # a session.
            srp_user.verify_session(base64.b64decode(auth_data["ServerProof"]))
            if not srp_user.authenticated():
                raise RuntimeError("SRP server proof mismatch — aborting login")

            if auth_data.get("2FA", {}).get("Enabled") or auth_data.get("TwoFactor"):
                raise RuntimeError(
                    "Account has 2FA enabled; SRP login cannot complete "
                    "without the TOTP code"
                )

            # 6. Tokens. The Proton WebMail flow returns the AccessToken in the
            # Set-Cookie header, NOT in the JSON body (the body only has Code,
            # UID, ServerProof, Scope). Trusting the body raises KeyError, so
            # the cookie jar is consulted first and the body second.
            uid = auth_data["UID"]
            # Tokens are bound to the verified UID by exact match. A prefix
            # match could bind a cookie left over from another session in the
            # jar and silently write it to the wrong account.
            jar = {c.name: c.value for c in auth_resp.cookies.jar}
            jar.update({c.name: c.value for c in client.cookies.jar})
            access = jar.get(f"AUTH-{uid}") or auth_data.get("AccessToken")
            refresh = jar.get(f"REFRESH-{uid}") or auth_data.get("RefreshToken")
            if not access:
                raise RuntimeError(
                    "auth succeeded but no AccessToken was issued "
                    f"(cookies={sorted(jar)})"
                )

            result = {
                "uid": uid,
                "access_token": access,
                "refresh_token": refresh,
                "scope": auth_data.get("Scope", ""),
                "key_salt": None,
            }
            if not fetch_key_salt:
                return result

            srp_headers = {
                "x-pm-uid": result["uid"],
                "Authorization": f"Bearer {result['access_token']}",
            }
            try:
                salts_resp = client.get("/core/v4/keys/salts", headers=srp_headers)
                if salts_resp.status_code != 200:
                    raise RuntimeError(f"keys/salts (SRP): {salts_resp.status_code}")
                salts_data = salts_resp.json()
                result["key_salt"] = (
                    salts_data.get("KeySalts", [{}])[0].get("KeySalt")
                )
                return result
            finally:
                # Close the temporary SRP session — leaving it open piles up
                # unused sessions on the server.
                try:
                    client.delete("/core/v4/auth", headers=srp_headers)
                except httpx.HTTPError as e:
                    log.debug("SRP logout failed: %s", e)

    # ── bcrypt key_password ──────────────────────────────────────────

    def _derive_key_password(self):
        """password + key_salt → bcrypt → key_password"""
        if not self.password:
            raise RuntimeError("Account password missing from config (password field)")
        if not self.key_salt:
            raise RuntimeError("KeySalt missing from config; run setup() first")

        key_salt_b64 = self.key_salt
        # Padding
        pad = len(key_salt_b64) % 4
        if pad:
            key_salt_b64 += "=" * (4 - pad)
        salt_raw = base64.b64decode(key_salt_b64)

        # Standard base64 → bcrypt base64 alphabet conversion
        std = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        bct = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        table = bytes.maketrans(std, bct)
        salt_b64 = base64.b64encode(salt_raw).translate(table)[:22]
        bcrypt_salt = b"$2y$10$" + salt_b64

        hashed = bcrypt.hashpw(self.password.encode(), bcrypt_salt)
        return hashed[29:].decode()

    # ── Inbox ────────────────────────────────────────────────────────

    def inbox(self, page=0, size=20, unread_only=False, label_id=0):
        """List inbox messages."""
        size = max(1, min(int(size), 150))  # API upper bound
        params = f"Page={int(page)}&PageSize={size}&LabelID={label_id}"
        if unread_only:
            params += "&Unread=1"
        data = self._api(f"/mail/v4/messages?{params}")
        return {
            "total": data.get("Total", 0),
            "page": page,
            "messages": [self._message_summary(m) for m in data.get("Messages", [])],
        }

    @staticmethod
    def _message_summary(m):
        return {
            "id": m["ID"],
            "from": m.get("SenderAddress", ""),
            "from_name": m.get("SenderName", ""),
            "subject": m.get("Subject", ""),
            "time": m.get("Time", 0),
            "unread": m.get("Unread", 0) == 1,
            "size": m.get("Size", 0),
            # The listing endpoint already returns ToList/CCList — no extra
            # call needed
            "to": [t.get("Address", "") for t in m.get("ToList", [])],
            "cc": [t.get("Address", "") for t in m.get("CCList", [])],
        }

    def search(self, query, size=50, max_pages=10, label_id=0):
        """Search over subject/sender — using Proton's own search filter.

        With the Keyword parameter, Proton /mail/v4/messages searches
        subject/sender server-side. Previously only the first page was filtered
        locally, so matches on the second page were lost.

        Args:
            size: Maximum number of messages to return.
            max_pages: Maximum number of pages to scan (infinite-loop brake).
        """
        from urllib.parse import quote_plus

        size = max(1, min(int(size), 150))
        keyword = quote_plus(query)
        messages = []
        total = 0
        for page in range(max_pages):
            data = self._api(
                f"/mail/v4/messages?Page={page}&PageSize=150"
                f"&LabelID={label_id}&Keyword={keyword}"
            )
            batch = data.get("Messages", [])
            total = data.get("Total", total)
            if not batch:
                break
            messages.extend(self._message_summary(m) for m in batch)
            if len(messages) >= size or len(batch) < 150:
                break
        return {"total": total, "query": query, "messages": messages[:size]}

    # ── Read message + decrypt ───────────────────────────────────────

    def read(self, message_id):
        """Read a message and decrypt it."""
        from urllib.parse import quote
        # Proton IDs are base64url — '-', '_', '=' must be preserved, only the
        # rest is encoded
        safe_id = quote(message_id, safe='-_=+/')
        data = self._api(f"/mail/v4/messages/{safe_id}")
        msg = data.get("Message", {})
        body = msg.get("Body", "")

        # If it is not PGP-encrypted, return it as-is
        if "BEGIN PGP" not in body:
            return {
                "id": msg.get("ID"),
                "from": msg.get("SenderAddress"),
                "from_name": msg.get("SenderName"),
                "to": [t.get("Address") for t in msg.get("ToList", [])],
                "subject": msg.get("Subject"),
                "time": msg.get("Time"),
                "body": body,
                "mime_type": msg.get("MIMEType"),
            }

        # Decrypt
        decrypted = self._decrypt_body(body, msg)
        return {
            "id": msg.get("ID"),
            "from": msg.get("SenderAddress"),
            "from_name": msg.get("SenderName"),
            "to": [t.get("Address") for t in msg.get("ToList", [])],
            "subject": msg.get("Subject"),
            "time": msg.get("Time"),
            "body": decrypted,
            "mime_type": msg.get("MIMEType"),
        }

    def _decrypt_body(self, body, msg=None):
        """PGP decrypt mail body. Tries all address keys via persistent worker."""
        from .crypto_worker import WorkerError, WorkerUnavailable, get_worker

        try:
            key_password = self._derive_key_password()
        except RuntimeError as e:
            return f"[key_password error: {e}]"

        address_keys = self.config.get("address_keys", {})
        primary_key = self.config.get("primary_key", "")

        # Sort keys — matching To address first
        to_addrs = []
        if msg:
            to_addrs = [t.get("Address", "").lower() for t in msg.get("ToList", [])]

        keys_to_try = []
        for email_key, info in address_keys.items():
            if any(email_key.lower() == t for t in to_addrs):
                keys_to_try.insert(0, info)
            else:
                keys_to_try.append(info)

        try:
            worker = get_worker()
        except WorkerUnavailable as e:
            return f"[crypto worker unavailable: {e}]"

        last_error = ""

        # Try each address key. A wrong key raises WorkerError (keep going);
        # a dead worker raises WorkerUnavailable (stop — retrying is pointless).
        for addr_key_info in keys_to_try:
            try:
                result = worker.decrypt(
                    key_password=key_password,
                    primary_key=primary_key,
                    body=body,
                    address_key=addr_key_info.get("private_key", ""),
                    token=addr_key_info.get("token", ""),
                )
                if result:
                    return result
            except WorkerUnavailable as e:
                return f"[crypto worker unavailable: {e}]"
            except WorkerError as e:
                last_error = str(e)[:200]
                continue

        # Fallback — primary key only
        try:
            return worker.decrypt(
                key_password=key_password,
                primary_key=primary_key,
                body=body,
            )
        except WorkerError as e:
            return f"[decrypt error: {last_error or e}]"

    # ── Wait / Polling ───────────────────────────────────────────────

    def wait(self, subject=None, from_filter=None, to_filter=None, timeout=60, interval=3):
        """Wait until a matching mail arrives (polling).
        to_filter: Filter on which address received it (subaddress included).

        Because the inbox() listing endpoint returns ToList/CCList, NO separate
        API call is made per message — critical for speed (N+1 is avoided)."""
        deadline = time.time() + timeout
        seen_ids = set()
        tf = to_filter.lower().strip() if to_filter else None
        while True:
            try:
                result = self.inbox(size=50, unread_only=True)
                for m in result["messages"]:
                    if m["id"] in seen_ids:
                        continue
                    seen_ids.add(m["id"])
                    if subject and subject.lower() not in m.get("subject", "").lower():
                        continue
                    if from_filter and from_filter.lower() not in m.get("from", "").lower():
                        continue
                    if tf:
                        addrs = [a.lower() for a in (m.get("to", []) + m.get("cc", []))]
                        joined = " ".join(addrs)
                        if "+" in tf.split("@", 1)[0]:
                            # tf is a full subaddress (foo+tag@x) -> ONLY an
                            # exact match. A base match would also match
                            # foo+other@x mails (wrong code!)
                            if tf not in addrs:
                                continue
                        else:
                            # tf is a base address (foo@x) -> exact OR
                            # subaddress base match
                            if tf not in joined and not self._addr_base_match(tf, addrs):
                                continue
                    return {"found": True, "message": m}
            except (RuntimeError, KeyError, httpx.HTTPError) as e:
                # A transient API error must not kill the polling — keep going
                # until the deadline
                log.warning("Polling error: %s", e)
            if time.time() >= deadline:
                break
            time.sleep(interval)
        return {"found": False, "message": None}

    @staticmethod
    def _addr_base_match(target, addr_list):
        """Compare target (foo+tag@x or foo@x) with the bases of the addresses
        in addr_list."""
        def base(e):
            e = (e or "").lower().strip()
            if "@" not in e:
                return e
            local, _, dom = e.partition("@")
            return f"{local.split('+', 1)[0]}@{dom}"
        tb = base(target)
        return any(base(a) == tb for a in addr_list)

    def wait_code(self, subject=None, from_filter=None, to_filter=None, timeout=120, interval=3):
        """Wait for a verification code — once the mail arrives, extract the
        code from the subject + body.
        to_filter: Filter on which address received it."""
        result = self.wait(subject=subject, from_filter=from_filter,
                           to_filter=to_filter, timeout=timeout, interval=interval)
        if not result["found"]:
            return None

        msg = self.read(result["message"]["id"])
        body = msg.get("body", "")
        subj = result["message"].get("subject", "") or msg.get("subject", "")

        return self._extract_code(subj, body)

    # Code fragments. The grouped form ("552-392", "123 456 789") requires at
    # least one separator; otherwise the alternative matches with zero
    # repetitions, the plain form never gets its turn, and 6-digit codes are
    # truncated to 4 digits.
    # In a grouped code the groups must be EQUAL in length (552-392,
    # 123 456 789). Phone numbers such as "0850 123 45 67" consist of unequal
    # groups; if mixed lengths were allowed, the first two groups of the number
    # would be mistaken for a code.
    _CODE_GROUPED = r'(?:\d{3}(?:[-\s]\d{3}){1,2}|\d{4}(?:[-\s]\d{4}){1,2})'
    _CODE_PLAIN = r'\d{4,10}'
    # Alphanumeric code (Steam "5KX2V", "a1b2c3"): 4-10 characters, must contain
    # BOTH letters and digits, and be in a single letter case. Mixed case
    # ("Verify") and pure letter sequences are words, not codes; both are
    # therefore excluded.
    _CODE_ALNUM = (r'(?:[A-Z0-9]{4,10}|[a-z0-9]{4,10})')
    _CODE_TOKEN = rf'({_CODE_GROUPED}|{_CODE_PLAIN})'
    # Context words — services do not stick to one language. Every new language
    # is one more alternative here; no code change is needed.
    #
    # These are match DATA, not prose: the literals must be spelled the way the
    # sending service spells them, in every script (Latin, Cyrillic, Arabic,
    # CJK, Hangul). Escaping some of them would only make the table harder to
    # read without changing what it matches.
    _CODE_CTX = (
        r'(?:'
        # en
        r'code|verification|verify|passcode|pass[-\s]?code|one[-\s]?time'
        r'|otp|2fa|mfa|pin|token|security[-\s]?code|access[-\s]?code'
        # tr
        r'|kod|kodu|kodunuz|doğrulama'
        # es/pt/it
        r'|código|codigo|codice|verificación|verificacion|verificação'
        r'|verificacao'
        r'|verifica'
        # de/nl
        r'|bestätigungscode|bestatigungscode|sicherheitscode|verificatiecode'
        # fr
        r'|vérification|verification'
        # pl/id/vi
        r'|weryfikacyjny|verifikasi|xác\s*minh|xac\s*minh'
        # ru/uk
        r'|код|подтверждения'
        # zh/ja/ko
        r'|验证码|認証コード|認証番号|인증번호|인증\s*코드'
        # ar
        r'|رمز|التحقق'
        r')'
    )

    # Markers that must NOT appear BEFORE a code:
    #   '#'       → hex colour (#123456 is not a code)
    #   ':' / '-' → a CSS value or a continuing digit group
    # and no CSS unit or decimal part may follow (600px, 1234.56).
    # A sentence-ending period ("your code is 889900.") is NOT a decimal: the
    # period is only banned when a digit follows it.
    _CODE_LEAD_BAN = r'(?<![#\d:\-])'
    _CODE_TRAIL_BAN = (r'(?!\s*(?:px|pt|em|rem|%|vh|vw|ex|ch|cm|mm|in|pc|deg|ms|s)\b)'
                       r'(?!\d)(?!\.\d)')

    # CSS bodies ("{ ... }"), functional colour notations and at-rules.
    # In broken mails such as an unclosed <style>, stripping tags is not enough,
    # so brace-delimited blocks are dropped at the text level as well.
    _CSS_BLOCK_RE = re.compile(r'\{[^{}]*\}')
    _CSS_AT_RULE_RE = re.compile(r'@[a-z-]+[^{;]*[{;]', re.IGNORECASE)
    _CSS_COLOR_FN_RE = re.compile(
        r'\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color-mix)\s*\([^)]*\)',
        re.IGNORECASE,
    )
    _MARKUP_RE = re.compile(r'(?s)<[^>]*>')
    # script/style with an opening but no closing tag: drop to end of input.
    _DANGLING_STYLE_RE = re.compile(r'(?is)<(?:script|style)\b.*')
    _STYLE_BLOCK_RE = re.compile(r'(?is)<(script|style)\b[^>]*>.*?</\1\s*>')
    _COMMENT_RE = re.compile(r'(?s)<!--.*?-->')
    _URL_RE = re.compile(r'\b[a-z][a-z0-9+.\-]*://\S+', re.IGNORECASE)

    # Codes split into boxes: <td>4</td><td>8</td>… or <b>48</b><b>39</b>…
    # Services display the code split across boxes; once the tags are replaced
    # with spaces it becomes "4 8 3 9 2 0" and no code pattern matches.
    # At least 3 consecutive short cells are joined.
    _CELL_TAGS = r'(?:td|th|span|b|strong|em|i|div|p|h[1-6]|font|code)'
    _SPLIT_CELL_RE = re.compile(
        rf'(?is)((?:<{_CELL_TAGS}\b[^>]*>\s*[A-Za-z0-9]{{1,4}}\s*'
        rf'</{_CELL_TAGS}\s*>\s*){{3,}})'
    )
    _CELL_CHAR_RE = re.compile(r'(?is)>\s*([A-Za-z0-9]{1,4})\s*<')

    @classmethod
    def _join_split_cells(cls, html):
        """Join consecutive short cells into a single token.

        They are only joined when the result is a plausible 4-10 character code;
        otherwise we would turn an ordinary table column (price, quantity) into
        a code. The original text is preserved, so cells that are not joined
        stay in the normal flow.
        """
        def _join(m):
            parts = cls._CELL_CHAR_RE.findall(m.group(1))
            joined = "".join(parts)
            if not 4 <= len(joined) <= 10:
                return m.group(1)
            # All cells must be single characters, or all must be digits only.
            if not (all(len(x) == 1 for x in parts) or all(x.isdigit() for x in parts)):
                return m.group(1)
            return f" {joined} "
        return cls._SPLIT_CELL_RE.sub(_join, html)

    @classmethod
    def _visible_text(cls, html):
        """Extract the visible text from an HTML body.

        Mail bodies are HTML; scanning the raw text makes style rules, tracking
        URLs and digits inside colour values look like codes. Order matters:
        comments and script/style blocks must be dropped BEFORE the tags,
        otherwise the CSS inside them survives as plain text.
        """
        if not html:
            return ""
        text = html
        # 1. Comments (including mso conditional blocks) — with the CSS inside.
        text = cls._COMMENT_RE.sub(" ", text)
        # 2. Closed script/style blocks, then the unclosed leftover.
        text = cls._STYLE_BLOCK_RE.sub(" ", text)
        text = cls._DANGLING_STYLE_RE.sub(" ", text)
        # 3. Join a code split across boxes before the tags are removed.
        text = cls._join_split_cells(text)
        # 4. Tags (this also takes the style="..." attributes with it).
        text = cls._MARKUP_RE.sub(" ", text)
        text = unescape(text)
        # 5. CSS left without tags: at-rules, brace blocks, colour functions.
        text = cls._CSS_AT_RULE_RE.sub(" ", text)
        text = cls._CSS_BLOCK_RE.sub(" ", text)
        text = cls._CSS_COLOR_FN_RE.sub(" ", text)
        # 6. URLs — tracking ids are not codes.
        text = cls._URL_RE.sub(" ", text)
        return re.sub(r'[ \t\xa0]+', ' ', text)

    def _extract_code(self, subject, body):
        """Extract the verification code from the subject + body.

        Supported formats:
          * 4-10 digit plain code (123456, 1234567)
          * code grouped with dashes/spaces (552-392, 123 456 789)
          * code split into boxes (<td>4</td><td>8</td>…)
          * alphanumeric code (Steam "5KX2V", "a1b2c3") — only with context

        Priority order:
          1. Numeric code next to context in the subject (most reliable)
          2. Numeric code next to context in the body's visible text
          3. Grouped code in the subject/body (the separator alone is telling)
          4. A standalone 6-digit number in the body
          5. Alphanumeric code next to context (riskiest — tried last)
        There is NO context-free "any 4-8 digit number" fallback — that prevents
        a year, an order number or a tracking id from being mistaken for a code.
        Hex colours (#123456) and values with CSS units (600000px) are not
        treated as codes either.
        """
        lead, trail = self._CODE_LEAD_BAN, self._CODE_TRAIL_BAN
        token = lead + self._CODE_TOKEN + trail
        ctx = self._CODE_CTX
        # There must be no digit between the context and the code, and no '#'
        # either, otherwise "code ... #123456" mistakes a hex colour for a code.
        gap = r'[^0-9#]{0,40}'
        # The context can come before the code ("code: 123456") as well as after
        # it ("123456 is your code"); both are searched.
        ctx_before = ctx + gap + token
        ctx_after = token + gap + ctx

        def _clean(m):
            # strip dashes/spaces -> pure digits
            return re.sub(r'[-\s]', '', m)

        body_text = self._visible_text(body)

        for haystack in (subject, body_text):
            if not haystack:
                continue
            for pattern in (ctx_before, ctx_after):
                m = re.search(pattern, haystack, re.IGNORECASE)
                if m:
                    return _clean(m.group(1))

        # Grouped code — the separator is itself a strong signal, no context
        # needed
        grouped = lead + f'({self._CODE_GROUPED})' + trail
        for haystack in (subject, body_text):
            if not haystack:
                continue
            m = re.search(grouped, haystack)
            if m:
                return _clean(m.group(1))

        # A standalone 6-digit number in the body (the most common code length)
        m = re.search(lead + r'(\d{6})' + trail, body_text)
        if m:
            return m.group(1)

        # Alphanumeric code — ONLY next to a context word. Searched without
        # context, every token like "Account" or "Hello2you" would look like a
        # code. Filler words can sit between the context and the code
        # ("code is 5KX2V", "your code: ABC123"), so up to 3 short words are
        # allowed.
        alnum = rf'(?<![A-Za-z0-9])({self._CODE_ALNUM})(?![A-Za-z0-9])'
        filler = r'(?:[^A-Za-z0-9]{0,10}(?:[a-z]{1,6}[^A-Za-z0-9]{0,10}){0,3})'
        for haystack in (subject, body_text):
            if not haystack:
                continue
            for pattern in (ctx + filler + alnum, alnum + filler + ctx):
                for m in re.finditer(pattern, haystack, re.IGNORECASE):
                    if self._is_alnum_code(m.group(1)):
                        return m.group(1)

        # no code found — do NOT return the raw body (it looks like a bogus code)
        return None

    @staticmethod
    def _is_alnum_code(token):
        """Is this alphanumeric token really a code?

        A code contains both letters and digits and is in a single case. That
        excludes pure words such as "Account" and mixed-case text such as
        "Verify2FA".
        """
        has_digit = any(ch.isdigit() for ch in token)
        has_alpha = any(ch.isalpha() for ch in token)
        if not (has_digit and has_alpha):
            return False
        letters = [ch for ch in token if ch.isalpha()]
        return all(c.isupper() for c in letters) or all(c.islower() for c in letters)

    # ── User info ────────────────────────────────────────────────────

    def user_info(self):
        """User information."""
        data = self._api("/core/v4/users")
        u = data["User"]
        return {
            "name": u["Name"],
            "email": self.email,
            "used_mb": u["UsedSpace"] // 1024 // 1024,
            "max_mb": u["MaxSpace"] // 1024 // 1024,
            "create_time": u["CreateTime"],
        }

    def addresses(self, use_cache=True):
        """List every address on the account (all pages + members).

        /core/v4/addresses returns at most 150 addresses per page; pagination
        follows the Total field. Addresses missing from the Members API are
        added as well.

        use_cache: When True, a cache with a 5 min TTL is used (Proton page 1
                   takes ~9s).
        """
        now = time.time()
        if use_cache and self._addr_cache is not None \
                and (now - self._addr_cache_time) < self._addr_cache_ttl:
            return self._addr_cache

        addr_map = {}
        for a in self._fetch_addresses_raw(with_keys=False):
            addr_map[a["email"].lower()] = a

        # Add addresses missing from the Members API as well. On personal
        # accounts this endpoint does not exist (403/422) — the address list is
        # still valid, so the error is not fatal.
        try:
            members_data = self._api("/core/v4/members")
        except (RuntimeError, httpx.HTTPError) as e:
            log.debug("members endpoint unavailable: %s", e)
            members_data = {}
        for m in members_data.get("Members", []):
            for a in m.get("Addresses", []):
                email_lower = a["Email"].lower()
                if email_lower not in addr_map:
                    keys = a.get("Keys", 0)
                    addr_map[email_lower] = {
                        "id": a["ID"],
                        "email": a["Email"],
                        "status": a.get("Status"),
                        "type": a.get("Type"),
                        "keys": keys if isinstance(keys, int) else len(keys),
                    }

        result = list(addr_map.values())
        self._addr_cache = result
        self._addr_cache_time = now
        return result

    def _invalidate_addr_cache(self):
        """Invalidate the address cache (must be called when an address
        changes)."""
        self._addr_cache = None
        self._addr_cache_time = 0

    def _fetch_addresses_raw(self, with_keys=False, max_pages=None):
        """Fetch every address, page by page.

        There is NO upper bound based on account type: a Business account may
        have thousands of aliases and all of them are fetched. PageSize=150 is
        Proton's own ceiling.

        Args:
            with_keys: When True, the raw API record (including Keys) is
                       returned. When False, a simplified dict is returned.
            max_pages: Infinite-loop brake. When None there is no limit — the
                       loop still stops once Total or a short page is reached.
        """
        PAGE_SIZE = 150  # API upper bound
        out = []
        seen = set()
        page = 0
        while True:
            data = self._api(
                f"/core/v4/addresses?Page={page}&PageSize={PAGE_SIZE}"
            )
            batch = data.get("Addresses", [])
            if not batch:
                break
            for a in batch:
                key = a["ID"]
                if key in seen:
                    continue
                seen.add(key)
                if with_keys:
                    out.append(a)
                else:
                    out.append({
                        "id": a["ID"],
                        "email": a["Email"],
                        "status": a.get("Status"),
                        "type": a.get("Type"),
                        "keys": len(a.get("Keys", [])),
                    })
            total = data.get("Total")
            if total is not None and len(seen) >= total:
                break
            if len(batch) < PAGE_SIZE:
                break
            page += 1
            if max_pages is not None and page >= max_pages:
                log.warning("Address pagination stopped at max_pages=%d "
                            "(%d fetched) — raise max_pages for more",
                            max_pages, len(seen))
                break
        return out

    def org_info(self):
        """Organization information."""
        data = self._api("/core/v4/organizations")
        org = data.get("Organization", {})
        return {
            "name": org.get("Name"),
            "max_members": org.get("MaxMembers"),
            "max_addresses": org.get("MaxAddresses"),
            "used_addresses": org.get("UsedAddresses"),
            "max_domains": org.get("MaxDomains"),
            "used_domains": org.get("UsedDomains"),
        }

    # ── Address creation ─────────────────────────────────────────────

    def create_address(self, local_part, domain="proton.me"):
        """
        Create a new @proton.me alias address — fully HTTP-based.
        1. POST /core/v4/addresses → create the address
        2. Generate a key (Node.js openpgp.js — patched, SHA-3 removed)
        3. POST /core/v4/keys/address → register the key

        Args:
            local_part: The part before the @ sign (e.g. "mynewaddr")
            domain: Domain name (default: proton.me)

        Returns:
            dict: {"email": "...", "address_id": "...", "fingerprint": "..."}
        """
        email = f"{local_part}@{domain}"

        # 1. Create the address
        addr_data = self._api("/core/v4/addresses", method="POST", json={
            "DisplayName": local_part,
            "Signature": "",
            "Local": local_part,
            "Domain": domain,
        })
        address = addr_data.get("Address", {})
        address_id = address.get("ID")
        if not address_id:
            raise RuntimeError(f"Address creation failed: {addr_data}")

        # 2. Generate a key
        key_data = self._generate_address_key(email)

        # 3. Register the key
        result = self._api("/core/v4/keys/address", method="POST", json={
            "AddressID": address_id,
            "Primary": 1,
            "PrivateKey": key_data["private_key"],
            "SignedKeyList": key_data["signed_key_list"],
            "Signature": key_data["signature"],
            "Token": key_data["token"],
        })
        if result.get("Code") != 1000:
            raise RuntimeError(f"Key registration failed: {result}")

        # Write the key LOCALLY as well. _decrypt_body only tries keys from
        # config["address_keys"]; if it is not added here, mail arriving at the
        # new address cannot be decrypted even though the key is registered with
        # Proton, and it stays that way until setup() is called again.
        self.config.setdefault("address_keys", {})[email] = {
            "address_id": address_id,
            "private_key": key_data["private_key"],
            "token": key_data["token"],
            "fingerprint": key_data["fingerprint"],
        }
        self._save_config()

        self._invalidate_addr_cache()
        return {
            "email": email,
            "address_id": address_id,
            "fingerprint": key_data["fingerprint"],
        }

    def create_addresses_batch(self, names, domain="proton.me"):
        """
        Bulk address creation — fully HTTP-based, no browser needed.
        Each address takes ~2-3 seconds.

        Args:
            names: List of address names (e.g. ["addr1", "addr2", ...])
            domain: Domain name (default: proton.me)

        Returns:
            list: [{"email": "...", "success": bool}, ...]
        """
        log.info("Creating %d addresses over HTTP", len(names))
        results = []
        for i, name in enumerate(names, start=1):
            email = f"{name}@{domain}"
            try:
                result = self.create_address(name, domain=domain)
                log.info("[%d/%d] %s created", i, len(names), email)
                results.append({"email": email, "success": True, **result})
            except (RuntimeError, KeyError, httpx.HTTPError) as e:
                err_msg = str(e).split("\n")[0][:200]
                log.warning("[%d/%d] %s failed: %s", i, len(names), email, err_msg)
                results.append({"email": email, "success": False, "error": err_msg})

        ok = sum(1 for r in results if r["success"])
        log.info("Created %d/%d addresses", ok, len(results))
        return results

    def _generate_address_key(self, email):
        """Generate new PGP address key via persistent worker."""
        from .crypto_worker import get_worker

        key_password = self._derive_key_password()
        primary_key = self.config.get("primary_key", "")

        worker = get_worker()
        return worker.generate_key(email, key_password, primary_key)

    def disable_address(self, address_id):
        """Disable an address — it stops receiving mail, the address stays.

        The address cache is dropped: otherwise addresses() would return the old
        `status` value for 5 minutes and the caller would think the address is
        still enabled.
        """
        result = self._api(f"/core/v4/addresses/{address_id}/disable",
                           method="PUT")
        self._invalidate_addr_cache()
        return result

    def enable_address(self, address_id):
        """Re-enable a disabled address."""
        result = self._api(f"/core/v4/addresses/{address_id}/enable",
                           method="PUT")
        self._invalidate_addr_cache()
        return result

    def delete_address(self, address_id, email=None):
        """Delete an address (only alias/secondary addresses can be deleted).

        Proton refuses to delete an enabled address (409, Code 2502:
        "Address is enabled. Please disable it before deleting"), so disabling
        before deleting happens right here — the caller does not have to
        memorize the two steps.

        Args:
            address_id: ID of the address to delete.
            email: When known, the local key record is cleaned up too. When
                   unknown, the record matching address_id is looked up.
        """
        disabled_here = False
        try:
            self.disable_address(address_id)
            disabled_here = True
        except RuntimeError as e:
            # If it is already disabled, Proton may still return a 4xx; the
            # delete attempt is the real check, so we do not stop here.
            log.debug("disable before delete failed (continuing): %s", e)

        try:
            result = self._api(f"/core/v4/addresses/{address_id}",
                               method="DELETE")
        except RuntimeError:
            # The delete was refused (e.g. Code 2011: only one address may be
            # deleted per year). If WE did the disabling, undo it — otherwise
            # the caller ends up with an address switched off without ever
            # asking for it, and mail sent to it starts being silently rejected.
            if disabled_here:
                try:
                    self.enable_address(address_id)
                    log.info("delete refused; re-enabled %s",
                             email or address_id)
                except RuntimeError as re_err:
                    log.error(
                        "delete refused AND re-enable failed for %s: %s — "
                        "the address is left disabled",
                        email or address_id, re_err,
                    )
            raise

        # Drop the local key record too: if it stays, _decrypt_body keeps trying
        # a dead key on every message.
        addr_keys = self.config.get("address_keys", {})
        stale = [
            e for e, info in addr_keys.items()
            if e == email or info.get("address_id") == address_id
        ]
        if stale:
            for e in stale:
                del addr_keys[e]
            self._save_config()

        self._invalidate_addr_cache()
        return result


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Proton Mail Reader")
    parser.add_argument("--config", required=True,
                        help="Account config file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging (token refresh, rate limit, etc.)")
    sub = parser.add_subparsers(dest="command")

    # inbox
    p_inbox = sub.add_parser("inbox", help="List the inbox")
    p_inbox.add_argument("--unread", action="store_true", help="Unread only")
    p_inbox.add_argument("--size", type=int, default=20, help="Page size")

    # read
    p_read = sub.add_parser("read", help="Read a message")
    p_read.add_argument("msg_id", help="Message ID")

    # search
    p_search = sub.add_parser("search", help="Search the inbox")
    p_search.add_argument("query", help="Search query")

    # wait
    p_wait = sub.add_parser("wait", help="Wait for mail (polling)")
    p_wait.add_argument("--subject", default="", help="Subject filter")
    p_wait.add_argument("--from", dest="from_filter", default="",
                        help="Sender filter")
    p_wait.add_argument("--timeout", type=int, default=60,
                        help="Timeout (seconds)")

    # code
    p_code = sub.add_parser("code", help="Wait for a verification code")
    p_code.add_argument("--subject", default="", help="Subject filter")
    p_code.add_argument("--from", dest="from_filter", default="",
                        help="Sender filter")
    p_code.add_argument("--timeout", type=int, default=120,
                        help="Timeout (seconds)")

    # login — session from scratch with email+password
    p_login = sub.add_parser(
        "login", help="Log in with email + password (CAPTCHA solved automatically)"
    )
    p_login.add_argument("--show-browser", action="store_true",
                         help="Run the CAPTCHA browser visibly (for debugging)")
    p_login.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                         help="Per-action delay in visible mode (ms), e.g. 300")
    p_login.add_argument("--keep-open", type=int, default=0, metavar="SEC",
                         help="Keep the browser open on failure (seconds)")

    # setup
    sub.add_parser("setup", help="Fetch key information from the API")

    # refresh
    sub.add_parser("refresh", help="Refresh the token")

    # user
    sub.add_parser("user", help="User information")

    # addresses
    sub.add_parser("addresses", help="List addresses")

    # create-address
    p_create = sub.add_parser("create-address",
                              help="Add a new @proton.me alias")
    p_create.add_argument("name", help="Address name (the part before the @)")
    p_create.add_argument("--domain", default="proton.me",
                          help="Domain (default: proton.me)")

    # disable-address / enable-address / delete-address
    for cmd, helptext in (
        ("disable-address", "Disable an address"),
        ("enable-address", "Re-enable a disabled address"),
        ("delete-address",
         "Delete an address (1 per year; it is disabled first)"),
    ):
        p = sub.add_parser(cmd, help=helptext)
        p.add_argument("address_id", help="Address ID (from the addresses command)")

    # org
    sub.add_parser("org", help="Organization information")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    reader = ProtonReader(args.config)
    try:
        _dispatch(parser, args, reader)
    finally:
        reader.close()


def _dispatch(parser, args, reader):
    if args.command == "inbox":
        result = reader.inbox(size=args.size, unread_only=args.unread)
        print(f"Total: {result['total']} messages")
        for m in result["messages"]:
            flag = "📩" if m["unread"] else "  "
            print(f"  {flag} [{m['id'][:12]}] {m['from'][:30]:30s} │ {m['subject'][:50]}")

    elif args.command == "read":
        msg = reader.read(args.msg_id)
        print(f"From:    {msg['from']} ({msg['from_name']})")
        print(f"Subject: {msg['subject']}")
        print(f"Time:    {msg['time']}")
        print("─" * 60)
        print(msg["body"])

    elif args.command == "search":
        result = reader.search(args.query)
        print(f"'{args.query}': {len(result['messages'])} results")
        for m in result["messages"]:
            print(f"  [{m['id'][:12]}] {m['from'][:30]:30s} │ {m['subject'][:50]}")

    elif args.command == "wait":
        print(f"Waiting for mail... (timeout={args.timeout}s)")
        result = reader.wait(
            subject=args.subject or None,
            from_filter=args.from_filter or None,
            timeout=args.timeout,
        )
        if result["found"]:
            m = result["message"]
            print(f"✅ Found: {m['from']} — {m['subject']}")
            print(f"   ID: {m['id']}")
        else:
            print("❌ Timed out — no mail found")

    elif args.command == "code":
        print(f"Waiting for a verification code... (timeout={args.timeout}s)")
        code = reader.wait_code(
            subject=args.subject or None,
            from_filter=args.from_filter or None,
            timeout=args.timeout,
        )
        if code:
            print(f"✅ Code: {code}")
        else:
            print("❌ No code found")

    elif args.command == "setup":
        data = reader.setup()
        print(json.dumps(data, indent=2))

    elif args.command == "login":
        data = reader.login(
            # None unless --show-browser is given: PROTON_HEADLESS decides.
            headless=False if args.show_browser else None,
            slow_mo=args.slow_mo,
            keep_open=args.keep_open,
        )
        print(json.dumps(data, indent=2))

    elif args.command == "refresh":
        reader.refresh()

    elif args.command == "user":
        info = reader.user_info()
        print(json.dumps(info, indent=2))

    elif args.command == "addresses":
        # A listing without ID and status is useless: the disable/delete
        # commands need the ID, and a disabled address would look identical to
        # an enabled one.
        # Measured: disable → Status=0 (Receive=0, Send=0), enable → Status=1.
        status_names = {0: "disabled", 1: "enabled"}
        for a in reader.addresses():
            status = status_names.get(a["status"], a["status"])
            kind = "primary" if a["type"] == 1 else "alias"
            print(f"  {a['email']}")
            print(f"    {kind}, {status}, {a['keys']} key(s)")
            print(f"    id: {a['id']}")

    elif args.command == "create-address":
        result = reader.create_address(args.name, domain=args.domain)
        print(json.dumps(result, indent=2))

    elif args.command == "disable-address":
        print(json.dumps(reader.disable_address(args.address_id), indent=2))

    elif args.command == "enable-address":
        print(json.dumps(reader.enable_address(args.address_id), indent=2))

    elif args.command == "delete-address":
        print(json.dumps(reader.delete_address(args.address_id), indent=2))

    elif args.command == "org":
        info = reader.org_info()
        print(json.dumps(info, indent=2))

    else:
        parser.print_help()


# Alias for public API
ProtonMailClient = ProtonReader


if __name__ == "__main__":
    main()
