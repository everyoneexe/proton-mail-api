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


# Proton'un insan doğrulaması istediğini bildiren API hata kodu.
HV_REQUIRED_CODE = 9001


class HumanVerificationRequired(RuntimeError):
    """Proton login için CAPTCHA/insan doğrulaması istiyor.

    Şifrenin yanlış olmasından ayrı tutulur: çağıran tarayıcıya düşüp
    puzzle'ı çözebilir, ama yanlış şifreyi tekrar denemenin anlamı yok.
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
        # reentrant: _api → refresh → _api zincirinde deadlock olmasın
        self._refresh_lock = threading.RLock()
        self._last_refresh_time = 0
        self._last_browser_login_time = 0
        # Adres listesi cache'i — Proton /addresses page 1 ~9s sürüyor, adresler nadir değişir
        self._addr_cache = None
        self._addr_cache_time = 0
        self._addr_cache_ttl = 300  # 5 dk
        # Tek httpx.Client — her istekte yeni Client açmak socket sızdırır.
        # Header/cookie'ler token yenilenince _sync_client_auth() ile güncellenir.
        self._http = httpx.Client(
            base_url="https://mail.proton.me/api",
            follow_redirects=False,
            timeout=30,
        )
        self._sync_client_auth()

    def close(self):
        """HTTP bağlantılarını kapat."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _load_config(self):
        """Config'i yükle.

        uid/auth_token ZORUNLU DEĞİL: yalnızca email+password içeren bir config
        geçerlidir, oturum login() ile SRP üzerinden açılır.
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
        """Config'i atomik ve 0600 izinle yaz.

        Doğrudan open(path, "w") yazmak dosyayı önce truncate eder; aynı config'e
        paralel refresh yapan ikinci bir süreç/thread araya girerse parola, token
        ve PGP private key'lerin tamamı kalıcı olarak kaybolur. Bu yüzden aynı
        dizine geçici dosya yazılıp os.replace ile atomik takas edilir.
        """
        directory = os.path.dirname(self.config_path) or "."
        fd, tmp_path = tempfile.mkstemp(
            dir=directory, prefix=".proton-config-", suffix=".tmp"
        )
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — sırlar dünyaya açık olmasın
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
        """Paylaşılan client'ın header/cookie'lerini config ile hizala."""
        self._http.headers.update(self._headers())
        self._http.cookies.clear()
        for name, val in self._cookie_jar().items():
            self._http.cookies.set(name, val)

    # Hesabın planından gelen scope'lar. Bunlar oturumun kilitli olmasından
    # değil, planın o özelliği hiç içermemesinden eksiktir; yeniden login
    # etmek döndürmez. (Ücretsiz hesapta alias için "organization" böyle.)
    _PLAN_SCOPES = frozenset({
        "organization", "vpn", "drive", "pass", "wallet", "docs", "meet",
    })

    def _api(self, path, method="GET", _retry=0, **kwargs):
        """API isteği yap. 401/403/429/5xx otomatik handle eder."""
        try:
            r = self._http.request(method.upper(), path, **kwargs)
        except httpx.HTTPError:
            # Connection hatası — retry
            if _retry < 2:
                time.sleep(2)
                return self._api(path, method=method, _retry=_retry + 1, **kwargs)
            raise

        # 401 — Token expired → refresh dene
        if r.status_code == 401 and _retry < 2:
            now = time.time()
            with self._refresh_lock:
                # 60sn içinde refresh yapıldıysa tekrar deneme — yeni token zaten var
                if now - self._last_refresh_time < 60:
                    log.debug("Token recently refreshed (cooldown); retrying request")
                    self._sync_client_auth()
                else:
                    self._last_refresh_time = now
                    log.info("Auth token expired; refreshing")
                    try:
                        self.refresh()
                    except (RuntimeError, OSError, ValueError, httpx.HTTPError) as e:
                        # REFRESH token da bozuksa browser login (cooldown ile)
                        log.warning("Token refresh failed (%s); trying browser login", e)
                        self._browser_relogin()
            return self._api(path, method=method, _retry=_retry + 1, **kwargs)

        # 403 — Scope yetersiz. İki ayrı sebep var ve yalnızca biri
        # login'le düzelir:
        #   * oturum kilitli/kısıtlı (scope: locked) → taze login yardım eder;
        #   * istenen scope hesabın PLANINDA yok (ör. organization: ücretsiz
        #     hesapta hiç verilmez) → yeniden login aynı 403'ü döndürür,
        #     tarayıcı açmak saf israftır.
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
                    # Cooldown'a takılırsa retry etmek anlamsız — aynı 403 döner.
                    if self._browser_relogin():
                        return self._api(path, method=method,
                                         _retry=_retry + 1, **kwargs)

        # 429 — Rate limited → bekle ve retry. Retry hakkı kalmadıysa beklemeden
        # hata atılır; boşa uyumak çağıranı gereksiz bloke eder.
        if r.status_code == 429 and _retry < 3:
            try:
                retry_after = int(r.headers.get("Retry-After", "10"))
            except ValueError:
                retry_after = 10
            retry_after = max(0, min(retry_after, 60))
            log.warning("Rate limited; waiting %ss", retry_after)
            time.sleep(retry_after)
            return self._api(path, method=method, _retry=_retry + 1, **kwargs)

        # 5xx — Sunucu hatası → retry
        if r.status_code >= 500 and _retry < 2:
            time.sleep(3)
            return self._api(path, method=method, _retry=_retry + 1, **kwargs)

        if r.status_code != 200:
            raise RuntimeError(f"API {path}: {r.status_code} — {r.text[:200]}")
        return r.json()

    def _browser_login_with_captcha(self, timeout=180, headless=None,
                                    slow_mo=0, keep_open=0):
        """Tarayıcıda login ol, puzzle CAPTCHA'yı otomatik çöz, oturumu al.

        SRP HTTP yolu insan doğrulaması istediğinde kullanılır. CAPTCHA
        tarayıcı içinde çözülmek zorunda: doğrulama isteği canvas üzerinde
        hesaplanan koordinatları ve `pcaptcha` header'ını taşıyor.

        Requires: pip install proton-mail-api[captcha]

        Args:
            headless: None ise PROTON_HEADLESS ortam değişkenine bakar
                      ("0" → görünür). Görünür mod hata ayıklama içindir:
                      puzzle'ın nerede patladığı ancak izlenerek görülür.
            slow_mo: Her Playwright eyleminden sonra beklenecek ms. Görünür
                     modda 250-500 arası izlemeyi kolaylaştırır.
            keep_open: Hata durumunda tarayıcıyı kapatmadan önce beklenecek
                       saniye. Görünür modda son ekranı incelemek için.
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
                    # Tarayıcı içi hatalar sessizce yutulmasın — puzzle'ın
                    # neden patladığı genelde burada görünür.
                    page.on("console", lambda m: log.debug("browser console [%s]: %s",
                                                           m.type, m.text))
                    page.on("pageerror", lambda e: log.warning("browser error: %s", e))

                    solver = PuzzleSolver()
                    # Dinleyiciler goto'dan ÖNCE kurulmalı: init/bg yanıtları
                    # sayfa yüklenirken geçiyor.
                    await solver.attach(page)

                    # Login'in gerçek verdikti /core/v4/auth yanıtıdır.
                    # Proton YANLIŞ şifrede de AUTH-<uid> cookie'si yazar
                    # (pre-auth session), bu yüzden cookie varlığı başarı
                    # kanıtı DEĞİLDİR: Code 1000 aranır.
                    verdict = {}

                    async def on_auth(resp):
                        if not resp.url.rstrip("/").endswith("/core/v4/auth"):
                            return
                        try:
                            body = await resp.json()
                        except (ValueError, PlaywrightError):
                            # Gövde JSON değil ya da yanıt artık okunamıyor
                            # (sayfa gitti). Verdict'i bozmadan geç.
                            return
                        if isinstance(body, dict) and "Code" in body:
                            verdict.clear()
                            verdict.update(body)

                    page.on("response", on_auth)

                    await page.goto("https://account.proton.me/login",
                                    timeout=60_000)
                    # Proton Account bir SPA: goto dönse bile ekranda hâlâ
                    # "Loading Proton Account.." olabilir ve form DOM'da yoktur.
                    # Sabit sleep yerine alanın kendisini bekle.
                    await page.wait_for_selector('input[id="username"]',
                                                 timeout=60_000)
                    await page.fill('input[id="username"]', username)
                    await page.fill('input[id="password"]', self.password)
                    await page.locator('button[type="submit"]').click()

                    # Tek bekleme döngüsü: verdict, CAPTCHA ve 2FA aynı anda
                    # izlenir; hangisi önce gelirse ona tepki verilir. CAPTCHA
                    # her zaman gelmez, o yüzden onu ayrıca beklemek yanlış.
                    uid = access = refresh = None
                    captcha_done = False

                    def read_tokens(jar, want_uid):
                        """Token'ları doğrulanmış UID'e bağla, herhangi bir
                        AUTH- cookie'sine değil."""
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

                        # CAPTCHA çıktıysa çöz; çözümden sonra Proton yeni bir
                        # /auth isteği yapar, o yüzden eski verdikti at.
                        if not captcha_done and await solver.has_iframe(page):
                            log.info("CAPTCHA appeared; solving")
                            await solver.solve_now(page)
                            captcha_done = True
                            verdict.clear()
                            continue

                        # 2FA ekranı geldiyse beklemenin anlamı yok.
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
                    # Teşhis: ekran görüntüsü + son URL. Hatayı yutmadan zenginleştir.
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

    _BROWSER_LOGIN_COOLDOWN = 120  # sn

    def _browser_relogin(self):
        """Browser ile login yapıp taze token al (tüm scope'larla).

        Cooldown burada zorunlu tutulur: her çağrı yeni bir headless Chromium
        başlatır, ve 401/403 merdiveni her istekte buraya düşebilir. Cooldown
        çağrı yerine bırakılırsa tek bir yetkisiz token istek başına bir tarayıcı
        açtırır.

        Returns:
            bool: Login denendiyse True, cooldown nedeniyle atlandıysa False.
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
                        # SPA: sabit sleep yavaş bağlantıda formu ıskalar.
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

    # ── Token refresh ────────────��───────────────────────────────────────

    def refresh(self):
        """REFRESH cookie ile yeni AUTH token al. Lock ile korunur.

        Not: Proton WebAccount/WebMail refresh'i yeni token'ları JSON body'de
        DEĞİL, Set-Cookie header'ında döner (AUTH-<uid>, REFRESH-<uid>,
        Session-Id, Tag). UID de değişir (RefreshCounter artar).
        """
        with self._refresh_lock:
            # REFRESH cookie'yi bul
            cookies = self.config.get("cookies", {})

            refresh_payload = None
            for name, val in cookies.items():
                if not name.startswith("REFRESH-"):
                    continue
                raw = val if isinstance(val, str) else val.get("value", "")
                try:
                    refresh_payload = json.loads(unquote(raw))
                except (ValueError, TypeError):
                    # Cookie ham refresh token'ı taşıyor (URL-encoded JSON değil)
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
                    "REFRESH cookie bulunamadı. Config'e REFRESH-{uid} cookie'si ekleyin."
                )

            # ClientID'ye uygun appversion seç (WebAccount → web-account, aksi WebMail)
            client_id = refresh_payload.get("ClientID", "WebMail")
            if client_id == "WebAccount":
                refresh_appversion = "web-account@5.0.999.0"
            else:
                refresh_appversion = APP_VERSION

            # Session cookie'lerini de gönder (refresh endpoint Session-Id ister)
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
                raise RuntimeError(f"Token yenileme başarısız: {data}")

            # Yeni token'ları Set-Cookie header'ından çek
            new_uid = data.get("UID", self.uid)
            resp_cookies = {c.name: c.value for c in r.cookies.jar}

            new_access = data.get("AccessToken")  # bazı client'larda body'de de olabilir
            new_refresh = data.get("RefreshToken")

            for cname, cval in resp_cookies.items():
                if cname.startswith("AUTH-"):
                    new_access = cval
                    new_uid = cname[len("AUTH-"):]
                elif cname.startswith("REFRESH-"):
                    # REFRESH cookie value = URL-encoded JSON; içinden RefreshToken çıkar
                    try:
                        rj = json.loads(unquote(cval or ""))
                        new_refresh = rj.get("RefreshToken", new_refresh)
                    except (ValueError, TypeError):
                        # Ham refresh token — JSON sarmalayıcı yok
                        new_refresh = cval

            if not new_access:
                raise RuntimeError(
                    f"Token yenileme: yeni AUTH token bulunamadı "
                    f"(cookies={list(resp_cookies.keys())})"
                )

            # auth_token güncelle
            self.auth_token = new_access
            self.config["auth_token"] = new_access
            auth_key = f"AUTH-{new_uid}"

            # Eski AUTH/REFRESH cookie'lerini temizle, yenilerini yaz
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

            # Session-Id / Tag güncelle (varsa)
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

    # ── Setup: API'den key bilgilerini çek ────────────────────────────

    def setup(self):
        """API'den PrimaryKey, Address keys çek ve config'e yaz.
        KeySalt için keys/salts endpoint'i lazım — eğer 403 alırsa
        key_salt'ı elle girmek gerekir veya SRP login ile çekilir."""

        # 1. User → PrimaryKey
        user_data = self._api("/core/v4/users")
        user = user_data["User"]
        user_keys = user.get("Keys", [])
        primary_key = user_keys[0]["PrivateKey"] if user_keys else None

        if primary_key:
            self.config["primary_key"] = primary_key

        # 2. KeySalt dene (403 olabilir — scope: locked)
        try:
            salts_data = self._api("/core/v4/keys/salts")
            key_salt = salts_data.get("KeySalts", [{}])[0].get("KeySalt")
            if key_salt:
                self.config["key_salt"] = key_salt
                self.key_salt = key_salt
                log.info("KeySalt fetched from keys/salts")
        except (RuntimeError, httpx.HTTPError) as e:
            log.warning("KeySalt fetch failed (scope:locked?): %s; trying SRP login", e)
            # SRP login ile KeySalt çekmeyi dene
            try:
                key_salt = self._srp_get_key_salt()
                if key_salt:
                    self.config["key_salt"] = key_salt
                    self.key_salt = key_salt
                    log.info("KeySalt fetched via SRP login")
            except (RuntimeError, ImportError, KeyError, httpx.HTTPError) as e2:
                log.warning("SRP KeySalt fetch failed: %s", e2)

        # 3. Addresses → Address keys (tüm sayfalar)
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
        """E-posta + şifre ile login yap, oturumu config'e yaz.

        Önce saf HTTP SRP denenir (hızlı, tarayıcı gerekmez). Proton insan
        doğrulaması isterse (HV / 9001) tarayıcıya düşülür ve puzzle CAPTCHA
        otomatik çözülür.

        Requires: pip install proton-mail-api[srp]
                  CAPTCHA fallback için ayrıca: proton-mail-api[captcha]

        Args:
            allow_captcha: False ise CAPTCHA istendiğinde tarayıcıya düşmez,
                           hata verir. Başsız sunucuda kasıtlı kullanım için.
            headless: CAPTCHA tarayıcısı gizli mi çalışsın. None → ortam
                      değişkeni PROTON_HEADLESS ("0" → görünür).
            slow_mo: Görünür modda eylem başına ms gecikme (izlemek için).
            keep_open: Hata anında tarayıcıyı açık tutma süresi (sn).

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
        """Yeni oturumu config'e yaz ve canlı client'ı hizala."""
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
            # SRP ham RefreshToken verir; tarayıcı cookie'si ise zaten
            # URL-encoded JSON zarfı taşır. İkinci kez sarmak refresh()'i bozar.
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
        """SRP login yaparak KeySalt çek — keys/salts 403 verdiğinde."""
        return self._srp_authenticate(fetch_key_salt=True)["key_salt"]

    def _srp_authenticate(self, fetch_key_salt=False):
        """Proton SRP akışını yürüt.

        Requires: pip install proton-mail-api[srp]

        Args:
            fetch_key_salt: True ise KeySalt da çekilir ve oturum kapatılır.
                            False ise oturum AÇIK bırakılır (login() kullanır).
        """
        if not self.password:
            raise RuntimeError("Şifre yok — SRP login yapılamaz")

        # SRP login gerekiyor — ağ isteğinden ÖNCE bağımlılıkları doğrula
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
            follow_redirects=False,  # Authorization header'ı redirect hedefine sızdırmasın
            timeout=30,
        ) as client:
            # 1. Auth info — salt, server challenge, modulus
            info_resp = client.post("/core/v4/auth/info", json={"Username": username})
            if info_resp.status_code != 200:
                raise RuntimeError(f"auth/info: {info_resp.status_code}")
            info = info_resp.json()

            # 2. Modulus imzasını DOĞRULA — sadece decrypt etmek yetmez.
            # Modulus, SRP'nin grup parametresidir. Sunucu (veya araya giren
            # biri) imzasız bir modulus verirse parola kanıtı kendi seçtiği
            # gruba karşı üretilir ve SRP'nin garantisi çöker.
            # python-gnupg imza geçersizse de veriyi döndürür; bu yüzden
            # `valid` bayrağı açıkça kontrol edilmelidir.
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

            # 3. İstemci kanıtı. process_challenge client proof (M) döndürür;
            # ephemeral (A) get_challenge()'dan gelir.
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
                # HV, 422 + Code 9001 olarak gelir. Yanlış şifreden ayırt
                # edilmeli: biri tarayıcıyla aşılabilir, diğeri aşılamaz.
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

            # 5. Sunucunun kanıtını doğrula — karşı tarafın şifreyi gerçekten
            # bildiğini kanıtlar. Atlanırsa sahte bir sunucu oturum verebilir.
            srp_user.verify_session(base64.b64decode(auth_data["ServerProof"]))
            if not srp_user.authenticated():
                raise RuntimeError("SRP server proof mismatch — aborting login")

            if auth_data.get("2FA", {}).get("Enabled") or auth_data.get("TwoFactor"):
                raise RuntimeError(
                    "Account has 2FA enabled; SRP login cannot complete "
                    "without the TOTP code"
                )

            # 6. Token'lar. Proton WebMail akışı AccessToken'ı JSON gövdesinde
            # DEĞİL, Set-Cookie header'ında döndürür (gövdede yalnızca Code,
            # UID, ServerProof, Scope var). Gövdeye güvenmek KeyError verir;
            # bu yüzden önce cookie jar'a, sonra gövdeye bakılır.
            uid = auth_data["UID"]
            # Token'lar doğrulanmış UID'e tam eşleşmeyle bağlanır. Prefix
            # eşleşmesi, jar'da kalmış başka bir oturumun cookie'sini
            # bağlayıp sessizce yanlış hesaba yazabilir.
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
                # Geçici SRP oturumunu kapat — açık kalırsa sunucuda
                # kullanılmayan bir session birikir.
                try:
                    client.delete("/core/v4/auth", headers=srp_headers)
                except httpx.HTTPError as e:
                    log.debug("SRP logout failed: %s", e)

    # ── bcrypt key_password ──────────────────────────────────────────

    def _derive_key_password(self):
        """password + key_salt → bcrypt → key_password"""
        if not self.password:
            raise RuntimeError("Hesap şifresi config'te yok (password alanı)")
        if not self.key_salt:
            raise RuntimeError("KeySalt config'te yok — önce setup() çalıştırın")

        key_salt_b64 = self.key_salt
        # Padding
        pad = len(key_salt_b64) % 4
        if pad:
            key_salt_b64 += "=" * (4 - pad)
        salt_raw = base64.b64decode(key_salt_b64)

        # Standard base64 → bcrypt base64 alfabe dönüşümü
        std = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        bct = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        table = bytes.maketrans(std, bct)
        salt_b64 = base64.b64encode(salt_raw).translate(table)[:22]
        bcrypt_salt = b"$2y$10$" + salt_b64

        hashed = bcrypt.hashpw(self.password.encode(), bcrypt_salt)
        return hashed[29:].decode()

    # ── Inbox ────────────────────────────────────────────────────────

    def inbox(self, page=0, size=20, unread_only=False, label_id=0):
        """Inbox mesajlarını listele."""
        size = max(1, min(int(size), 150))  # API üst sınırı
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
            # Listeleme endpoint'i ToList/CCList'i zaten döndürür — ek çağrı gereksiz
            "to": [t.get("Address", "") for t in m.get("ToList", [])],
            "cc": [t.get("Address", "") for t in m.get("CCList", [])],
        }

    def search(self, query, size=50, max_pages=10, label_id=0):
        """Konu/gönderen üzerinde arama — Proton'un kendi arama filtresiyle.

        Proton /mail/v4/messages, Keyword parametresiyle sunucu tarafında
        subject/sender araması yapar. Eskiden sadece ilk sayfa yerelde
        filtreleniyordu; ikinci sayfadaki eşleşmeler kaybediliyordu.

        Args:
            size: Döndürülecek maksimum mesaj sayısı.
            max_pages: Taranacak maksimum sayfa (sonsuz döngü freni).
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

    # ── Mesaj oku + decrypt ──────────────────────────────────────────

    def read(self, message_id):
        """Mesajı oku ve decrypt et."""
        from urllib.parse import quote
        # Proton ID'leri base64url — '-', '_', '=' korunmalı, sadece diğerleri encode
        safe_id = quote(message_id, safe='-_=+/')
        data = self._api(f"/mail/v4/messages/{safe_id}")
        msg = data.get("Message", {})
        body = msg.get("Body", "")

        # PGP şifreli değilse doğrudan döndür
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

    # ── Bekle / Polling ──────────────────────────────────────────────

    def wait(self, subject=None, from_filter=None, to_filter=None, timeout=60, interval=3):
        """Eşleşen mail gelene kadar bekle (polling).
        to_filter: Hangi adrese geldiğini filtrele (subaddress dahil).

        inbox() listeleme endpoint'i ToList/CCList'i döndürdüğü için her mesaj
        için ayrı API çağrısı YAPILMAZ — hız için kritik (N+1 önlenir)."""
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
                            # tf tam subaddress (foo+tag@x) → SADECE tam eşleşme.
                            # base match yapılırsa foo+other@x mailleri de eşleşir (yanlış kod!)
                            if tf not in addrs:
                                continue
                        else:
                            # tf base adres (foo@x) → tam VEYA subaddress base eşleşmesi
                            if tf not in joined and not self._addr_base_match(tf, addrs):
                                continue
                    return {"found": True, "message": m}
            except (RuntimeError, KeyError, httpx.HTTPError) as e:
                # Geçici API hatası polling'i düşürmesin — deadline'a kadar devam
                log.warning("Polling error: %s", e)
            if time.time() >= deadline:
                break
            time.sleep(interval)
        return {"found": False, "message": None}

    @staticmethod
    def _addr_base_match(target, addr_list):
        """target (foo+tag@x veya foo@x) ile addr_list'teki adreslerin base'lerini karşılaştır."""
        def base(e):
            e = (e or "").lower().strip()
            if "@" not in e:
                return e
            local, _, dom = e.partition("@")
            return f"{local.split('+', 1)[0]}@{dom}"
        tb = base(target)
        return any(base(a) == tb for a in addr_list)

    def wait_code(self, subject=None, from_filter=None, to_filter=None, timeout=120, interval=3):
        """Doğrulama kodu bekle — mail gelince subject + body'den kodu çıkar.
        to_filter: Hangi adrese geldiğini filtrele."""
        result = self.wait(subject=subject, from_filter=from_filter,
                           to_filter=to_filter, timeout=timeout, interval=interval)
        if not result["found"]:
            return None

        msg = self.read(result["message"]["id"])
        body = msg.get("body", "")
        subj = result["message"].get("subject", "") or msg.get("subject", "")

        return self._extract_code(subj, body)

    # Kod parçaları. Gruplu biçim ("552-392", "123 456 789") en az bir ayırıcı
    # ister; aksi halde alternatif sıfır tekrarla eşleşip düz biçime hiç sıra
    # gelmez ve 6 haneli kodlar 4 haneye kesilir.
    # Gruplu kodda grupların uzunluğu EŞİT olmalı (552-392, 123 456 789).
    # "0850 123 45 67" gibi telefon numaraları eşit olmayan gruplardan oluşur;
    # karışık uzunluğa izin verilirse numaranın ilk iki grubu kod sanılır.
    _CODE_GROUPED = r'(?:\d{3}(?:[-\s]\d{3}){1,2}|\d{4}(?:[-\s]\d{4}){1,2})'
    _CODE_PLAIN = r'\d{4,10}'
    # Alfanümerik kod (Steam "5KX2V", "a1b2c3"): 4-10 karakter, harf VE rakam
    # içermeli, tek bir harf durumunda olmalı. Karışık durum ("Verify") ve saf
    # harf dizileri kelimedir, kod değildir; bu yüzden ikisi de dışlanır.
    _CODE_ALNUM = (r'(?:[A-Z0-9]{4,10}|[a-z0-9]{4,10})')
    _CODE_TOKEN = rf'({_CODE_GROUPED}|{_CODE_PLAIN})'
    # Bağlam sözcükleri — servisler tek bir dil kullanmıyor. Her yeni dil burada
    # bir alternatif; kod tarafında değişiklik gerekmez.
    _CODE_CTX = (
        r'(?:'
        # en
        r'code|verification|verify|passcode|pass[-\s]?code|one[-\s]?time'
        r'|otp|2fa|mfa|pin|token|security[-\s]?code|access[-\s]?code'
        # tr
        r'|kod|kodu|kodunuz|doğrulama'
        # es/pt/it
        r'|código|codigo|codice|verificación|verificacion|verificação|verificacao'
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

    # Bir kodun ÖNÜNDE bulunmaması gereken işaretler:
    #   '#'       → hex renk (#123456 kod değil)
    #   ':' / '-' → CSS değeri veya devam eden rakam grubu
    # ve SONRASINDA CSS birimi veya ondalık kısım olmamalı (600px, 1234.56).
    # Cümle sonu noktası ("kodunuz 889900.") ondalık DEĞİLDİR: nokta yalnızca
    # ardından rakam gelirse yasaklanır.
    _CODE_LEAD_BAN = r'(?<![#\d:\-])'
    _CODE_TRAIL_BAN = (r'(?!\s*(?:px|pt|em|rem|%|vh|vw|ex|ch|cm|mm|in|pc|deg|ms|s)\b)'
                       r'(?!\d)(?!\.\d)')

    # CSS gövdeleri ("{ ... }"), fonksiyonel renk gösterimleri ve at-kuralları.
    # Kapanmamış <style> gibi bozuk maillerde etiket temizliği yetmez, bu yüzden
    # süslü parantezli bloklar metin düzeyinde de atılır.
    _CSS_BLOCK_RE = re.compile(r'\{[^{}]*\}')
    _CSS_AT_RULE_RE = re.compile(r'@[a-z-]+[^{;]*[{;]', re.IGNORECASE)
    _CSS_COLOR_FN_RE = re.compile(
        r'\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color-mix)\s*\([^)]*\)',
        re.IGNORECASE,
    )
    _MARKUP_RE = re.compile(r'(?s)<[^>]*>')
    # Açılışı olan ama kapanışı olmayan script/style: satır sonuna kadar at.
    _DANGLING_STYLE_RE = re.compile(r'(?is)<(?:script|style)\b.*')
    _STYLE_BLOCK_RE = re.compile(r'(?is)<(script|style)\b[^>]*>.*?</\1\s*>')
    _COMMENT_RE = re.compile(r'(?s)<!--.*?-->')
    _URL_RE = re.compile(r'\b[a-z][a-z0-9+.\-]*://\S+', re.IGNORECASE)

    # Kutucuklara bölünmüş kodlar: <td>4</td><td>8</td>… veya <b>48</b><b>39</b>…
    # Servisler kodu kutulara bölerek gösteriyor; etiketler boşlukla
    # değiştirilince "4 8 3 9 2 0" olur ve hiçbir kod deseni eşleşmez.
    # En az 3 ardışık kısa hücre birleştirilir.
    _CELL_TAGS = r'(?:td|th|span|b|strong|em|i|div|p|h[1-6]|font|code)'
    _SPLIT_CELL_RE = re.compile(
        rf'(?is)((?:<{_CELL_TAGS}\b[^>]*>\s*[A-Za-z0-9]{{1,4}}\s*'
        rf'</{_CELL_TAGS}\s*>\s*){{3,}})'
    )
    _CELL_CHAR_RE = re.compile(r'(?is)>\s*([A-Za-z0-9]{1,4})\s*<')

    @classmethod
    def _join_split_cells(cls, html):
        """Ardışık kısa hücreleri tek bir jetona birleştir.

        Sadece 4-10 karakterlik makul bir kod oluşuyorsa birleştirilir; aksi
        halde sıradan bir tablo sütununu (fiyat, adet) koda dönüştürürdük.
        Orijinal metin korunur, böylece birleşmeyen hücreler normal akışta kalır.
        """
        def _join(m):
            parts = cls._CELL_CHAR_RE.findall(m.group(1))
            joined = "".join(parts)
            if not 4 <= len(joined) <= 10:
                return m.group(1)
            # Tüm hücreler tek karakter, ya da tümü sadece rakam olmalı.
            if not (all(len(x) == 1 for x in parts) or all(x.isdigit() for x in parts)):
                return m.group(1)
            return f" {joined} "
        return cls._SPLIT_CELL_RE.sub(_join, html)

    @classmethod
    def _visible_text(cls, html):
        """HTML gövdeden görünür metni çıkar.

        Mail gövdeleri HTML; ham metinde taranırsa stil kuralları, tracking
        URL'leri ve renk değerlerindeki rakamlar kod sanılır. Sırası önemli:
        yorumlar ve script/style blokları etiketlerden ÖNCE atılmalı, yoksa
        içlerindeki CSS düz metin olarak kalır.
        """
        if not html:
            return ""
        text = html
        # 1. Yorumlar (mso koşullu blokları dahil) — içindeki CSS ile birlikte.
        text = cls._COMMENT_RE.sub(" ", text)
        # 2. Kapanışlı script/style blokları, ardından kapanmamış kalıntı.
        text = cls._STYLE_BLOCK_RE.sub(" ", text)
        text = cls._DANGLING_STYLE_RE.sub(" ", text)
        # 3. Kutucuklara bölünmüş kodu etiketler silinmeden önce birleştir.
        text = cls._join_split_cells(text)
        # 4. Etiketler (style="..." niteliklerini de götürür).
        text = cls._MARKUP_RE.sub(" ", text)
        text = unescape(text)
        # 5. Etiketsiz kalan CSS: at-kuralları, süslü bloklar, renk fonksiyonları.
        text = cls._CSS_AT_RULE_RE.sub(" ", text)
        text = cls._CSS_BLOCK_RE.sub(" ", text)
        text = cls._CSS_COLOR_FN_RE.sub(" ", text)
        # 6. URL'ler — tracking id'leri kod değildir.
        text = cls._URL_RE.sub(" ", text)
        return re.sub(r'[ \t\xa0]+', ' ', text)

    def _extract_code(self, subject, body):
        """Subject + body'den doğrulama kodunu çıkar.

        Desteklenen biçimler:
          * 4-10 haneli düz kod (123456, 1234567)
          * tire/boşlukla gruplanmış kod (552-392, 123 456 789)
          * kutucuklara bölünmüş kod (<td>4</td><td>8</td>…)
          * alfanümerik kod (Steam "5KX2V", "a1b2c3") — yalnızca bağlam varsa

        Öncelik sırası:
          1. Subject'te bağlama komşu sayısal kod (en güvenilir)
          2. Gövdenin görünür metninde bağlama komşu sayısal kod
          3. Subject/gövdede gruplu kod (ayırıcı tek başına ayırt edici)
          4. Gövdede tek başına 6 haneli sayı
          5. Bağlama komşu alfanümerik kod (en riskli — en sonda)
        Bağlamsız "herhangi bir 4-8 haneli sayı" fallback'i YOK — yıl, sipariş
        numarası ve tracking id'yi kod sanmasını önler. Hex renkler (#123456) ve
        CSS birimli değerler (600000px) de kod sayılmaz.
        """
        lead, trail = self._CODE_LEAD_BAN, self._CODE_TRAIL_BAN
        token = lead + self._CODE_TOKEN + trail
        ctx = self._CODE_CTX
        # Bağlam ile kod arasında rakam olmamalı; '#' de olmamalı, yoksa
        # "code ... #123456" hex rengini kod sanar.
        gap = r'[^0-9#]{0,40}'
        # Bağlam koddan önce de ("code: 123456") sonra da ("123456 is your code")
        # gelebilir; ikisi de aranır.
        ctx_before = ctx + gap + token
        ctx_after = token + gap + ctx

        def _clean(m):
            # tire/boşlukları sil → saf rakam
            return re.sub(r'[-\s]', '', m)

        body_text = self._visible_text(body)

        for haystack in (subject, body_text):
            if not haystack:
                continue
            for pattern in (ctx_before, ctx_after):
                m = re.search(pattern, haystack, re.IGNORECASE)
                if m:
                    return _clean(m.group(1))

        # Gruplu kod — ayırıcı kendisi güçlü sinyal, bağlam gerekmez
        grouped = lead + f'({self._CODE_GROUPED})' + trail
        for haystack in (subject, body_text):
            if not haystack:
                continue
            m = re.search(grouped, haystack)
            if m:
                return _clean(m.group(1))

        # Gövdede tek başına 6 haneli (en yaygın kod uzunluğu)
        m = re.search(lead + r'(\d{6})' + trail, body_text)
        if m:
            return m.group(1)

        # Alfanümerik kod — SADECE bağlam sözcüğünün yanında. Bağlamsız aranırsa
        # her "Account", "Hello2you" gibi jeton kod sanılır.
        # Bağlam ile kod arasına dolgu sözcükleri girebilir ("code is 5KX2V",
        # "kodunuz: ABC123"), o yüzden en fazla 3 kısa kelimeye izin verilir.
        alnum = rf'(?<![A-Za-z0-9])({self._CODE_ALNUM})(?![A-Za-z0-9])'
        filler = r'(?:[^A-Za-z0-9]{0,10}(?:[a-z]{1,6}[^A-Za-z0-9]{0,10}){0,3})'
        for haystack in (subject, body_text):
            if not haystack:
                continue
            for pattern in (ctx + filler + alnum, alnum + filler + ctx):
                for m in re.finditer(pattern, haystack, re.IGNORECASE):
                    if self._is_alnum_code(m.group(1)):
                        return m.group(1)

        return None  # kod bulunamadı — ham body DÖNDÜRME (yanlış kod izlenimi verir)

    @staticmethod
    def _is_alnum_code(token):
        """Alfanümerik jeton gerçekten kod mu?

        Kod hem harf hem rakam içerir ve tek durumdadır. Bu, "Account" gibi saf
        kelimeleri ve "Verify2FA" gibi karışık durumlu metni dışlar.
        """
        has_digit = any(ch.isdigit() for ch in token)
        has_alpha = any(ch.isalpha() for ch in token)
        if not (has_digit and has_alpha):
            return False
        letters = [ch for ch in token if ch.isalpha()]
        return all(c.isupper() for c in letters) or all(c.islower() for c in letters)

    # ── User info ────────────────────────────────────────────────────

    def user_info(self):
        """Kullanıcı bilgisi."""
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
        """Hesaptaki tüm adresleri listele (tüm sayfalar + members).

        /core/v4/addresses sayfa başına en fazla 150 adres döner; Total alanına
        göre sayfalanır. Members API'den eksik adresler de eklenir.

        use_cache: True ise 5 dk TTL'li cache kullanır (Proton page 1 ~9s).
        """
        now = time.time()
        if use_cache and self._addr_cache is not None \
                and (now - self._addr_cache_time) < self._addr_cache_ttl:
            return self._addr_cache

        addr_map = {}
        for a in self._fetch_addresses_raw(with_keys=False):
            addr_map[a["email"].lower()] = a

        # Members API'den eksik adresleri de ekle. Kişisel hesaplarda bu endpoint
        # yoktur (403/422) — adres listesi yine geçerli, o yüzden hata ölümcül değil.
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
        """Adres cache'ini geçersiz kıl (yeni adres eklenince çağrılmalı)."""
        self._addr_cache = None
        self._addr_cache_time = 0

    def _fetch_addresses_raw(self, with_keys=False, max_pages=None):
        """Tüm adresleri sayfalayarak çek.

        Hesap tipine göre hiçbir üst sınır YOK: Business hesabında binlerce alias
        olabilir, hepsi çekilir. PageSize=150 Proton'un kendi tavanı.

        Args:
            with_keys: True ise ham API kaydını (Keys dahil) döndürür.
                       False ise sadeleştirilmiş dict döndürür.
            max_pages: Sonsuz döngü freni. None ise sınırsız — döngü yine de
                       Total'a veya kısa sayfaya ulaşınca durur.
        """
        PAGE_SIZE = 150  # API üst sınırı
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
        """Organizasyon bilgisi."""
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

    # ── Adres ekleme ─────────────────────────────────────────────────

    def create_address(self, local_part, domain="proton.me"):
        """
        Yeni @proton.me alias adresi oluştur — tamamen HTTP tabanlı.
        1. POST /core/v4/addresses → adres oluştur
        2. Key üret (Node.js openpgp.js — patched, SHA-3 kaldırıldı)
        3. POST /core/v4/keys/address → key kaydet

        Args:
            local_part: @ işaretinden önceki kısım (ör: "mynewaddr")
            domain: domain adı (varsayılan: proton.me)

        Returns:
            dict: {"email": "...", "address_id": "...", "fingerprint": "..."}
        """
        email = f"{local_part}@{domain}"

        # 1. Adres oluştur
        addr_data = self._api("/core/v4/addresses", method="POST", json={
            "DisplayName": local_part,
            "Signature": "",
            "Local": local_part,
            "Domain": domain,
        })
        address = addr_data.get("Address", {})
        address_id = address.get("ID")
        if not address_id:
            raise RuntimeError(f"Adres oluşturulamadı: {addr_data}")

        # 2. Key üret
        key_data = self._generate_address_key(email)

        # 3. Key'i kaydet
        result = self._api("/core/v4/keys/address", method="POST", json={
            "AddressID": address_id,
            "Primary": 1,
            "PrivateKey": key_data["private_key"],
            "SignedKeyList": key_data["signed_key_list"],
            "Signature": key_data["signature"],
            "Token": key_data["token"],
        })
        if result.get("Code") != 1000:
            raise RuntimeError(f"Key kayıt hatası: {result}")

        # Anahtarı YERELE de yaz. _decrypt_body yalnızca
        # config["address_keys"] üzerinden dener; buraya eklenmezse yeni
        # adrese gelen mail, Proton'da anahtar kayıtlı olmasına rağmen
        # çözülemez ve setup() tekrar çağrılana kadar öyle kalır.
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
        Toplu adres ekleme — tamamen HTTP tabanlı, browser gerekmez.
        Her adres ~2-3 saniye sürer.

        Args:
            names: adres isimlerinin listesi (ör: ["addr1", "addr2", ...])
            domain: domain adı (varsayılan: proton.me)

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
        """Adresi devre dışı bırak — mail almayı durdurur, adres durur.

        Adres cache'i düşürülür: aksi halde addresses() 5 dakika boyunca
        eski `status` değerini döndürür ve çağıran adresi hâlâ etkin sanır.
        """
        result = self._api(f"/core/v4/addresses/{address_id}/disable",
                           method="PUT")
        self._invalidate_addr_cache()
        return result

    def enable_address(self, address_id):
        """Devre dışı bırakılmış adresi tekrar aç."""
        result = self._api(f"/core/v4/addresses/{address_id}/enable",
                           method="PUT")
        self._invalidate_addr_cache()
        return result

    def delete_address(self, address_id, email=None):
        """Adresi sil (sadece alias/secondary adresler silinebilir).

        Proton etkin bir adresi silmeyi reddeder (409, Code 2502:
        "Address is enabled. Please disable it before deleting"), bu yüzden
        silme öncesi devre dışı bırakma burada yapılır — çağıranın iki adımı
        ezberlemesi gerekmez.

        Args:
            address_id: Silinecek adresin ID'si.
            email: Biliniyorsa, yerel anahtar kaydı da temizlenir. Bilinmiyorsa
                   address_id ile eşleşen kayıt aranır.
        """
        disabled_here = False
        try:
            self.disable_address(address_id)
            disabled_here = True
        except RuntimeError as e:
            # Zaten devre dışıysa Proton yine 4xx döndürebilir; silme denemesi
            # asıl doğrulama, bu yüzden burada durmuyoruz.
            log.debug("disable before delete failed (continuing): %s", e)

        try:
            result = self._api(f"/core/v4/addresses/{address_id}",
                               method="DELETE")
        except RuntimeError:
            # Silme reddedildi (ör. Code 2011: yılda yalnızca bir adres
            # silinebilir). Devre dışı bırakmayı BİZ yaptıysak geri al —
            # yoksa çağıran hiç istemediği halde adresi kapatmış olur ve
            # o adrese gelen mail sessizce reddedilmeye başlar.
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

        # Yerel anahtar kaydını da düş: kalırsa _decrypt_body her mesajda
        # ölü bir anahtarı denemeye devam eder.
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
                        help="Hesap config dosyası (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Ayrıntılı günlük (token yenileme, rate limit, vb.)")
    sub = parser.add_subparsers(dest="command")

    # inbox
    p_inbox = sub.add_parser("inbox", help="Inbox listele")
    p_inbox.add_argument("--unread", action="store_true", help="Sadece okunmamış")
    p_inbox.add_argument("--size", type=int, default=20, help="Sayfa boyutu")

    # read
    p_read = sub.add_parser("read", help="Mesaj oku")
    p_read.add_argument("msg_id", help="Mesaj ID'si")

    # search
    p_search = sub.add_parser("search", help="Inbox'ta ara")
    p_search.add_argument("query", help="Arama sorgusu")

    # wait
    p_wait = sub.add_parser("wait", help="Mail bekle (polling)")
    p_wait.add_argument("--subject", default="", help="Konu filtresi")
    p_wait.add_argument("--from", dest="from_filter", default="", help="Gönderen filtresi")
    p_wait.add_argument("--timeout", type=int, default=60, help="Zaman aşımı (sn)")

    # code
    p_code = sub.add_parser("code", help="Doğrulama kodu bekle")
    p_code.add_argument("--subject", default="", help="Konu filtresi")
    p_code.add_argument("--from", dest="from_filter", default="", help="Gönderen filtresi")
    p_code.add_argument("--timeout", type=int, default=120, help="Zaman aşımı (sn)")

    # login — email+password ile sıfırdan oturum
    p_login = sub.add_parser(
        "login", help="E-posta + şifre ile login (CAPTCHA otomatik çözülür)"
    )
    p_login.add_argument("--show-browser", action="store_true",
                         help="CAPTCHA tarayıcısını görünür çalıştır (hata ayıklama)")
    p_login.add_argument("--slow-mo", type=int, default=0, metavar="MS",
                         help="Görünür modda eylem başına gecikme (ms), ör. 300")
    p_login.add_argument("--keep-open", type=int, default=0, metavar="SN",
                         help="Hata anında tarayıcıyı açık tut (sn)")

    # setup
    sub.add_parser("setup", help="API'den key bilgilerini çek")

    # refresh
    sub.add_parser("refresh", help="Token yenile")

    # user
    sub.add_parser("user", help="Kullanıcı bilgisi")

    # addresses
    sub.add_parser("addresses", help="Adresleri listele")

    # create-address
    p_create = sub.add_parser("create-address", help="Yeni @proton.me alias ekle")
    p_create.add_argument("name", help="Adres ismi (@ işaretinden önceki kısım)")
    p_create.add_argument("--domain", default="proton.me", help="Domain (varsayılan: proton.me)")

    # disable-address / enable-address / delete-address
    for cmd, helptext in (
        ("disable-address", "Adresi devre dışı bırak"),
        ("enable-address", "Devre dışı adresi tekrar aç"),
        ("delete-address", "Adresi sil (yılda 1 hak; önce devre dışı bırakılır)"),
    ):
        p = sub.add_parser(cmd, help=helptext)
        p.add_argument("address_id", help="Adres ID'si (addresses komutundan)")

    # org
    sub.add_parser("org", help="Organizasyon bilgisi")

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
        print(f"Toplam: {result['total']} mesaj")
        for m in result["messages"]:
            flag = "📩" if m["unread"] else "  "
            print(f"  {flag} [{m['id'][:12]}] {m['from'][:30]:30s} │ {m['subject'][:50]}")

    elif args.command == "read":
        msg = reader.read(args.msg_id)
        print(f"Kimden: {msg['from']} ({msg['from_name']})")
        print(f"Konu:   {msg['subject']}")
        print(f"Zaman:  {msg['time']}")
        print("─" * 60)
        print(msg["body"])

    elif args.command == "search":
        result = reader.search(args.query)
        print(f"'{args.query}' için {len(result['messages'])} sonuç:")
        for m in result["messages"]:
            print(f"  [{m['id'][:12]}] {m['from'][:30]:30s} │ {m['subject'][:50]}")

    elif args.command == "wait":
        print(f"Mail bekleniyor... (timeout={args.timeout}s)")
        result = reader.wait(
            subject=args.subject or None,
            from_filter=args.from_filter or None,
            timeout=args.timeout,
        )
        if result["found"]:
            m = result["message"]
            print(f"✅ Bulundu: {m['from']} — {m['subject']}")
            print(f"   ID: {m['id']}")
        else:
            print("❌ Zaman aşımı — mail bulunamadı")

    elif args.command == "code":
        print(f"Doğrulama kodu bekleniyor... (timeout={args.timeout}s)")
        code = reader.wait_code(
            subject=args.subject or None,
            from_filter=args.from_filter or None,
            timeout=args.timeout,
        )
        if code:
            print(f"✅ Kod: {code}")
        else:
            print("❌ Kod bulunamadı")

    elif args.command == "setup":
        data = reader.setup()
        print(json.dumps(data, indent=2))

    elif args.command == "login":
        data = reader.login(
            # --show-browser verilmezse None: karar PROTON_HEADLESS'a kalır.
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
        # ID ve status olmadan liste işe yaramaz: disable/delete komutları ID
        # ister, ve devre dışı bir adres etkin olanla aynı görünürdü.
        # Ölçüldü: disable → Status=0 (Receive=0, Send=0), enable → Status=1.
        status_names = {0: "devre dışı", 1: "etkin"}
        for a in reader.addresses():
            status = status_names.get(a["status"], a["status"])
            kind = "birincil" if a["type"] == 1 else "alias"
            print(f"  {a['email']}")
            print(f"    {kind}, {status}, {a['keys']} anahtar")
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
