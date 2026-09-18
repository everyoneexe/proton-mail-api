"""
Proton puzzle CAPTCHA solver — login akışında çıkan "Human Verification".

Proton, şifre doğru olsa bile login'de puzzle CAPTCHA isteyebilir. SRP akışı
saf HTTP'dir ama CAPTCHA tarayıcı içinde çözülmek zorunda: doğrulama isteği
`pcaptcha` header'ı ve canvas üzerinde hesaplanan koordinatlarla gidiyor.

Çözüm üç parçadan oluşur:

1. **Delik bulma (OpenCV).** Arka plan görselindeki puzzle boşluğu, beyaz
   kontura komşu koyu bölge olarak aranır. Şeffaf siyah delikler için "relative
   dark" (bulanıklaştırılmış görüntüden fark), tam siyah delikler için "absolute
   dark" eşiklemesi kullanılır; iki adaydan alanı büyük olan seçilir.
2. **Proof-of-work.** Proton `init` yanıtında N tane challenge ve gereken
   sıfır sayısını verir; her challenge için sha256 önek koşulunu sağlayan sayı
   bulunur. Süreç havuzunda paralel hesaplanır (CPU-bound).
3. **Parçayı taşıma.** Canvas'a tıklanıp ok tuşlarıyla (adım = 2px) parça
   hedefe götürülür. Fare sürüklemesi yerine ok tuşu: koordinatı tarayıcının
   kendisi hesaplar, bizim piksel tahminimiz doğrulama isteğine girmez.

Requires: pip install proton-mail-api[captcha]  (playwright + opencv + numpy)
"""

import asyncio
import hashlib
import json
import logging
from concurrent.futures import ProcessPoolExecutor

log = logging.getLogger(__name__)

# PIXI sahne sabitleri — Proton'un captcha canvas'ından.
# answer = {x: sprite.x - 32, y: sprite.y - 82}, arka plan y ofseti 50.
_SPRITE_X0 = 32
_SPRITE_Y0 = 32
_ANSWER_X_OFF = 32
_ANSWER_Y_OFF = 82
_BG_Y_OFF = 50
_ARROW_STEP = 2  # ok tuşu başına piksel


class CaptchaError(RuntimeError):
    """CAPTCHA çözülemedi."""


def _pow_single(challenge, n_zeros):
    """Bir challenge için sha256 önek koşulunu sağlayan sayıyı bul."""
    n = (n_zeros + 3) // 4
    threshold = 2 ** (n * 4 - n_zeros)
    for i in range(10_000_000):
        h = hashlib.sha256(f"{i}{challenge}".encode()).hexdigest()
        if int(h[:n], 16) < threshold:
            return i
    raise CaptchaError(f"Proof-of-work çözülemedi: {challenge}")


def solve_pow(challenges, n_zeros, workers=None):
    """Tüm challenge'ları paralel çöz. CPU-bound olduğu için süreç havuzu."""
    if not challenges:
        return []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(_pow_single, challenges, [n_zeros] * len(challenges)))


def find_hole(bg_bytes):
    """Arka plandaki puzzle deliğini bul, (answer_x, answer_y) döndür.

    Delik, beyaz konturla çevrili koyu bölgedir. Tek bir eşik yetmez: bazı
    delikler şeffaf (arka planı koyultur), bazıları tam siyahtır. İkisi ayrı
    maskelenip birleştirilir, en büyük aday seçilir.

    Raises:
        CaptchaError: Delik bulunamazsa. Sıfır koordinat döndürmek sessizce
            yanlış cevap göndermek olur; hata vermek doğrusu.
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        raise ImportError(
            "opencv-python and numpy are required to solve the puzzle CAPTCHA. "
            "Install with: pip install proton-mail-api[captcha]"
        )

    bg = cv2.imdecode(np.frombuffer(bg_bytes, np.uint8), cv2.IMREAD_COLOR)
    if bg is None:
        raise CaptchaError("CAPTCHA arka planı çözümlenemedi (bozuk görsel)")
    gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    h_img, w_img = bg.shape[:2]

    # Deliğin beyaz konturu — genişletilip maske olarak kullanılır.
    _, white = cv2.threshold(gray, 200, 255, cv2.THRESH_BINARY)
    white_dilated = cv2.dilate(white, np.ones((5, 5), np.uint8), iterations=3)

    def candidates(dark_mask):
        mask = cv2.bitwise_and(dark_mask, white_dilated)
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
        contours, _ = cv2.findContours(
            mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
        )
        out = []
        for c in contours:
            area = cv2.contourArea(c)
            if area < 200:
                continue
            _, _, cw, ch = cv2.boundingRect(c)
            # Parça boyutu makul olmalı: çok küçük = gürültü, çok büyük = sahne.
            if cw < 20 or ch < 20:
                continue
            if cw > w_img * 0.5 or ch > h_img * 0.5:
                continue
            aspect = cw / ch if ch else 0
            if not 0.3 <= aspect <= 3.0:
                continue
            out.append((area, c))
        return out

    # Şeffaf delikler: yerel ortalamadan belirgin koyu olan bölgeler.
    blur = cv2.GaussianBlur(gray, (21, 21), 0)
    diff = np.clip(blur.astype(int) - gray.astype(int), 0, 255).astype(np.uint8)
    _, dark_rel = cv2.threshold(diff, 15, 255, cv2.THRESH_BINARY)
    # Tam siyah delikler.
    _, dark_abs = cv2.threshold(gray, 80, 255, cv2.THRESH_BINARY_INV)

    found = candidates(dark_rel) + candidates(dark_abs)
    if not found:
        raise CaptchaError("Puzzle deliği bulunamadı")

    hole = max(found, key=lambda c: c[0])[1]
    x, y, cw, ch = cv2.boundingRect(hole)
    cx, cy = x + cw // 2, y + ch // 2
    answer_x = cx - _ANSWER_X_OFF
    answer_y = (cy + _BG_Y_OFF) - _ANSWER_Y_OFF
    log.info("CAPTCHA hole at (%d,%d) → answer (%d,%d)", cx, cy, answer_x, answer_y)
    return answer_x, answer_y


def arrow_steps(answer_x, answer_y):
    """Hedefe ulaşmak için gereken (yatay, dikey) ok tuşu adımı."""
    steps_x = (answer_x + _ANSWER_X_OFF - _SPRITE_X0) // _ARROW_STEP
    steps_y = (answer_y + _ANSWER_Y_OFF - _SPRITE_Y0) // _ARROW_STEP
    return steps_x, steps_y


class PuzzleSolver:
    """Bir Playwright sayfasına bağlanıp puzzle CAPTCHA'yı çözer.

    Kullanım:
        solver = PuzzleSolver()
        await solver.attach(page)      # goto'dan ÖNCE — ağ dinleyicileri kurar
        ...                            # login formunu doldur
        await solver.solve(page)       # CAPTCHA çıktıysa çöz
    """

    def __init__(self, pow_workers=None):
        self.bg_bytes = None
        self.init_data = None
        self.answers = None
        self._pow_workers = pow_workers

    async def attach(self, page):
        """Ağ dinleyicilerini kur. Sayfa yüklenmeden ÖNCE çağrılmalı.

        `bg` ve `init` yanıtları yakalanır; `validate` isteğine çözülmüş PoW
        cevapları enjekte edilir. Koordinatlar tarayıcının kendi hesabıdır —
        yalnızca `answers` alanı değiştirilir.
        """
        async def on_response(resp):
            try:
                if "captcha/v1/api/bg" in resp.url and resp.status == 200:
                    self.bg_bytes = await resp.body()
                    log.debug("CAPTCHA background captured (%d bytes)",
                              len(self.bg_bytes))
                elif "captcha/v1/api/init" in resp.url and resp.status == 200:
                    self.init_data = await resp.json()
                    log.info("CAPTCHA init: %d challenges, %d leading zeros",
                             len(self.init_data.get("challenges", [])),
                             self.init_data.get("nLeadingZerosRequired", 0))
            except Exception as e:  # noqa: BLE001 — dinleyici asla patlamamalı
                log.debug("CAPTCHA response handler: %s", e)

        async def on_validate(route):
            if not self.init_data or self.answers is None:
                await route.continue_()
                return
            headers = await route.request.all_headers()
            try:
                pcaptcha = json.loads(headers.get("pcaptcha", "{}"))
            except ValueError:
                pcaptcha = {}
            pcaptcha["answers"] = self.answers
            new_headers = {k: v for k, v in headers.items() if not k.startswith(":")}
            new_headers["pcaptcha"] = json.dumps(pcaptcha)
            log.info("CAPTCHA validate: x=%s y=%s",
                     pcaptcha.get("x"), pcaptcha.get("y"))
            await route.continue_(headers=new_headers)

        page.on("response", on_response)
        await page.route("**/captcha/v1/api/validate**", on_validate)

    @staticmethod
    async def has_iframe(page):
        """CAPTCHA iframe'i şu anda var mı? Beklemez.

        Çağıran kendi bekleme döngüsünü yürütürken kullanılır: login sonrası
        cookie de captcha da gelebilir, hangisi önce gelirse ona tepki verilir.
        """
        for frame in await page.locator("iframe").all():
            title = await frame.get_attribute("title")
            if title and "captcha" in title.lower():
                return True
        return False

    @classmethod
    async def is_present(cls, page, timeout=15):
        """CAPTCHA iframe'i belirene kadar bekle. Yoksa False."""
        for _ in range(timeout):
            if await cls.has_iframe(page):
                return True
            await asyncio.sleep(1)
        return False

    # Teşhis çıktıları. Puzzle yanlış yere sürüklendiğinde tek anlamlı kanıt
    # bunlar: ham arka plan ve tespit edilen deliğin işaretlenmiş hali.
    DEBUG_BG = "/tmp/proton-captcha-bg.png"
    DEBUG_MARKED = "/tmp/proton-captcha-detected.png"

    def _dump_debug(self, answer_x, answer_y):
        """Arka planı ve bulunan deliği diske yaz (hata ayıklama)."""
        try:
            import cv2
            import numpy as np

            with open(self.DEBUG_BG, "wb") as f:
                f.write(self.bg_bytes)
            img = cv2.imdecode(np.frombuffer(self.bg_bytes, np.uint8),
                               cv2.IMREAD_COLOR)
            # answer → delik merkezi (find_hole'un tersi)
            cx = answer_x + _ANSWER_X_OFF
            cy = answer_y + _ANSWER_Y_OFF - _BG_Y_OFF
            cv2.drawMarker(img, (cx, cy), (0, 0, 255), cv2.MARKER_CROSS, 40, 2)
            cv2.circle(img, (cx, cy), 28, (0, 0, 255), 2)
            cv2.imwrite(self.DEBUG_MARKED, img)
            log.info("CAPTCHA debug images: %s (raw), %s (detected hole at %d,%d)",
                     self.DEBUG_BG, self.DEBUG_MARKED, cx, cy)
        except Exception as e:  # noqa: BLE001 — teşhis asla akışı bozmamalı
            log.debug("CAPTCHA debug dump failed: %s", e)

    async def solve(self, page, timeout=30):
        """CAPTCHA belirene kadar bekle, çık(tıy)sa çöz.

        Returns:
            bool: Çözüldüyse True, CAPTCHA hiç çıkmadıysa False.

        Raises:
            CaptchaError: CAPTCHA var ama çözülemedi.
        """
        if not await self.is_present(page, timeout=timeout):
            log.debug("No CAPTCHA present")
            return False
        return await self.solve_now(page, timeout=timeout)

    async def solve_now(self, page, timeout=30):
        """CAPTCHA'yı hemen çöz — iframe'in zaten var olduğu varsayılır.

        Çağıran kendi bekleme döngüsünü yürütüyorsa bu kullanılır; `solve`
        iframe'i beklemek için fazladan tur harcar.
        """

        # init ve bg ağ yanıtlarını bekle
        for _ in range(timeout * 2):
            if self.init_data and self.bg_bytes:
                break
            await asyncio.sleep(0.5)
        if not self.init_data:
            raise CaptchaError(
                "CAPTCHA init verisi alınamadı — Proton akışı değişmiş olabilir"
            )
        if not self.bg_bytes:
            raise CaptchaError("CAPTCHA arka plan görseli alınamadı")

        # PoW — validate isteği gelmeden hazır olmalı
        loop = asyncio.get_running_loop()
        self.answers = await loop.run_in_executor(
            None, solve_pow,
            self.init_data["challenges"],
            self.init_data["nLeadingZerosRequired"],
            self._pow_workers,
        )
        log.info("CAPTCHA proof-of-work solved (%d answers)", len(self.answers))

        try:
            answer_x, answer_y = find_hole(self.bg_bytes)
        except CaptchaError:
            # Delik bulunamadı — ham arka planı bırak, gözle bakılabilsin.
            self._dump_debug(_ANSWER_X_OFF, _ANSWER_Y_OFF - _BG_Y_OFF)
            raise
        self._dump_debug(answer_x, answer_y)
        steps_x, steps_y = arrow_steps(answer_x, answer_y)

        frame = next(
            (f for f in page.frames if "captcha/v1/assets" in f.url), None
        )
        if frame is None:
            raise CaptchaError("CAPTCHA assets frame bulunamadı")

        # Canvas'a odaklan, parçayı ok tuşlarıyla taşı. Fare sürüklemesi
        # yerine ok tuşu: son koordinatı tarayıcı hesaplar.
        await frame.locator("canvas").click()
        await page.wait_for_timeout(300)
        for _ in range(abs(steps_x)):
            await page.keyboard.press("ArrowRight" if steps_x > 0 else "ArrowLeft")
        for _ in range(abs(steps_y)):
            await page.keyboard.press("ArrowDown" if steps_y > 0 else "ArrowUp")
        log.info("CAPTCHA piece moved: %d horizontal, %d vertical steps",
                 steps_x, steps_y)
        await page.wait_for_timeout(300)

        # "Next" etkinleşene kadar bekle ve tıkla
        for _ in range(15):
            btn = frame.locator("button.btn-solid-purple")
            if await btn.count() > 0 and await btn.get_attribute("disabled") is None:
                await btn.click()
                log.info("CAPTCHA submitted")
                return True
            await asyncio.sleep(1)
        raise CaptchaError("CAPTCHA 'Next' butonu etkinleşmedi")
