"""
Proton puzzle CAPTCHA solver — the "Human Verification" step of the login flow.

Proton may demand a puzzle CAPTCHA at login even when the password is correct.
The SRP flow is pure HTTP, but the CAPTCHA has to be solved inside a browser:
the validate request goes out with the `pcaptcha` header and with coordinates
computed on the canvas.

The solution consists of three parts:

1. **Hole detection (OpenCV).** The puzzle gap in the background image is
   searched for as a dark region adjacent to a white contour. For transparent
   black holes a "relative dark" mask is used (the difference against a
   blurred copy of the image), for fully black holes an "absolute dark"
   threshold; of the two candidates the one with the larger area is picked.
2. **Proof-of-work.** Proton's `init` response supplies N challenges and the
   required number of zeros; for each challenge a number satisfying the sha256
   prefix condition is found. Computed in parallel in a process pool
   (CPU-bound).
3. **Moving the piece.** The canvas is clicked and the piece is walked to the
   target with the arrow keys (step = 2px). Arrow keys instead of a mouse
   drag: the browser itself computes the coordinate, so our own pixel guess
   never enters the validate request.

Requires: pip install proton-mail-api[captcha]  (playwright + opencv + numpy)
"""

import asyncio
import hashlib
import json
import logging
from concurrent.futures import ProcessPoolExecutor

log = logging.getLogger(__name__)

# PIXI scene constants — from Proton's captcha canvas.
# answer = {x: sprite.x - 32, y: sprite.y - 82}, background y offset 50.
_SPRITE_X0 = 32
_SPRITE_Y0 = 32
_ANSWER_X_OFF = 32
_ANSWER_Y_OFF = 82
_BG_Y_OFF = 50
_ARROW_STEP = 2  # pixels per arrow key press


class CaptchaError(RuntimeError):
    """CAPTCHA could not be solved."""


def _pow_single(challenge, n_zeros):
    """Find a number satisfying the sha256 prefix condition for a challenge.

    Counts up from zero, hashing f"{i}{challenge}", until the digest starts
    with `n_zeros` zero bits — i.e. until its leading hex nibbles, read as an
    integer, fall below `threshold`.
    """
    n = (n_zeros + 3) // 4
    threshold = 2 ** (n * 4 - n_zeros)
    for i in range(10_000_000):
        h = hashlib.sha256(f"{i}{challenge}".encode()).hexdigest()
        if int(h[:n], 16) < threshold:
            return i
    raise CaptchaError(f"Proof-of-work unsolved: {challenge}")


def solve_pow(challenges, n_zeros, workers=None):
    """Solve every challenge in parallel. A process pool, since it is CPU-bound."""
    if not challenges:
        return []
    with ProcessPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(_pow_single, challenges, [n_zeros] * len(challenges)))


def find_hole(bg_bytes):
    """Find the puzzle hole in the background, return (answer_x, answer_y).

    The hole is a dark region surrounded by a white contour. A single
    threshold does not suffice: some holes are transparent (they darken the
    background), others are fully black. The two are masked separately and
    then merged, and the largest candidate is selected.

    Raises:
        CaptchaError: If the hole is not found. Returning zero coordinates
            would mean silently submitting a wrong answer; raising is the
            correct behaviour.
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
        raise CaptchaError("CAPTCHA background could not be decoded (corrupt image)")
    gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)
    h_img, w_img = bg.shape[:2]

    # The white contour of the hole — dilated and used as a mask.
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
            # Piece size must be plausible: too small = noise, too big = scene.
            if cw < 20 or ch < 20:
                continue
            if cw > w_img * 0.5 or ch > h_img * 0.5:
                continue
            aspect = cw / ch if ch else 0
            if not 0.3 <= aspect <= 3.0:
                continue
            out.append((area, c))
        return out

    # Transparent holes: regions noticeably darker than the local average.
    blur = cv2.GaussianBlur(gray, (21, 21), 0)
    diff = np.clip(blur.astype(int) - gray.astype(int), 0, 255).astype(np.uint8)
    _, dark_rel = cv2.threshold(diff, 15, 255, cv2.THRESH_BINARY)
    # Fully black holes.
    _, dark_abs = cv2.threshold(gray, 80, 255, cv2.THRESH_BINARY_INV)

    found = candidates(dark_rel) + candidates(dark_abs)
    if not found:
        raise CaptchaError("Puzzle hole not found")

    hole = max(found, key=lambda c: c[0])[1]
    x, y, cw, ch = cv2.boundingRect(hole)
    cx, cy = x + cw // 2, y + ch // 2
    answer_x = cx - _ANSWER_X_OFF
    answer_y = (cy + _BG_Y_OFF) - _ANSWER_Y_OFF
    log.info("CAPTCHA hole at (%d,%d) → answer (%d,%d)", cx, cy, answer_x, answer_y)
    return answer_x, answer_y


def arrow_steps(answer_x, answer_y):
    """The (horizontal, vertical) arrow key steps needed to reach the target.

    The piece starts at the PIXI sprite origin (_SPRITE_X0, _SPRITE_Y0) and
    every arrow key press shifts it by _ARROW_STEP (2) pixels, so the distance
    from that origin to the answer coordinate divided by the step size gives
    the number of presses.
    """
    steps_x = (answer_x + _ANSWER_X_OFF - _SPRITE_X0) // _ARROW_STEP
    steps_y = (answer_y + _ANSWER_Y_OFF - _SPRITE_Y0) // _ARROW_STEP
    return steps_x, steps_y


class PuzzleSolver:
    """Attaches to a Playwright page and solves the puzzle CAPTCHA.

    Usage:
        solver = PuzzleSolver()
        await solver.attach(page)      # BEFORE goto — installs net listeners
        ...                            # fill in the login form
        await solver.solve(page)       # solve the CAPTCHA if one appeared
    """

    def __init__(self, pow_workers=None):
        self.bg_bytes = None
        self.init_data = None
        self.answers = None
        self._pow_workers = pow_workers

    async def attach(self, page):
        """Install the network listeners. MUST be called BEFORE the page loads.

        The `bg` and `init` responses fly past while the page is loading, so
        the listeners have to be in place beforehand. They capture those two
        responses, and the solved PoW answers are injected into the `validate`
        request. The coordinates are the browser's own computation — only the
        `answers` field is modified.
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
            except Exception as e:  # noqa: BLE001 — a listener must never blow up
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
        """Is a CAPTCHA iframe present right now? Does not wait.

        Used while the caller runs its own wait loop: after login either the
        cookie or the CAPTCHA may arrive, and whichever comes first is the one
        reacted to.
        """
        for frame in await page.locator("iframe").all():
            title = await frame.get_attribute("title")
            if title and "captcha" in title.lower():
                return True
        return False

    @classmethod
    async def is_present(cls, page, timeout=15):
        """Wait until the CAPTCHA iframe appears. False if there is none."""
        for _ in range(timeout):
            if await cls.has_iframe(page):
                return True
            await asyncio.sleep(1)
        return False

    # Diagnostic dumps. When the puzzle gets dragged to the wrong place these
    # are the only meaningful evidence: the raw background and the detected
    # hole marked on it.
    DEBUG_BG = "/tmp/proton-captcha-bg.png"
    DEBUG_MARKED = "/tmp/proton-captcha-detected.png"

    def _dump_debug(self, answer_x, answer_y):
        """Write the background and the detected hole to disk (debugging)."""
        try:
            import cv2
            import numpy as np

            with open(self.DEBUG_BG, "wb") as f:
                f.write(self.bg_bytes)
            img = cv2.imdecode(np.frombuffer(self.bg_bytes, np.uint8),
                               cv2.IMREAD_COLOR)
            # answer → hole centre (the inverse of find_hole)
            cx = answer_x + _ANSWER_X_OFF
            cy = answer_y + _ANSWER_Y_OFF - _BG_Y_OFF
            cv2.drawMarker(img, (cx, cy), (0, 0, 255), cv2.MARKER_CROSS, 40, 2)
            cv2.circle(img, (cx, cy), 28, (0, 0, 255), 2)
            cv2.imwrite(self.DEBUG_MARKED, img)
            log.info("CAPTCHA debug images: %s (raw), %s (detected hole at %d,%d)",
                     self.DEBUG_BG, self.DEBUG_MARKED, cx, cy)
        except Exception as e:  # noqa: BLE001 — diagnostics must never break flow
            log.debug("CAPTCHA debug dump failed: %s", e)

    async def solve(self, page, timeout=30):
        """Wait until the CAPTCHA appears and solve it if it did.

        Returns:
            bool: True if solved, False if no CAPTCHA ever appeared.

        Raises:
            CaptchaError: A CAPTCHA is present but could not be solved.
        """
        if not await self.is_present(page, timeout=timeout):
            log.debug("No CAPTCHA present")
            return False
        return await self.solve_now(page, timeout=timeout)

    async def solve_now(self, page, timeout=30):
        """Solve the CAPTCHA right away — the iframe is assumed to exist.

        This is what a caller running its own wait loop uses; `solve` spends
        extra rounds waiting for the iframe.
        """

        # wait for the init and bg network responses
        for _ in range(timeout * 2):
            if self.init_data and self.bg_bytes:
                break
            await asyncio.sleep(0.5)
        if not self.init_data:
            raise CaptchaError(
                "CAPTCHA init data never arrived; Proton's flow may have changed"
            )
        if not self.bg_bytes:
            raise CaptchaError("CAPTCHA background image never arrived")

        # PoW — must be ready before the validate request goes out
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
            # Hole not found — dump the raw background so it can be eyeballed.
            self._dump_debug(_ANSWER_X_OFF, _ANSWER_Y_OFF - _BG_Y_OFF)
            raise
        self._dump_debug(answer_x, answer_y)
        steps_x, steps_y = arrow_steps(answer_x, answer_y)

        frame = next(
            (f for f in page.frames if "captcha/v1/assets" in f.url), None
        )
        if frame is None:
            raise CaptchaError("CAPTCHA assets frame not found")

        # Focus the canvas, move the piece with the arrow keys. Arrow keys
        # instead of a mouse drag: the browser computes the final coordinate.
        await frame.locator("canvas").click()
        await page.wait_for_timeout(300)
        for _ in range(abs(steps_x)):
            await page.keyboard.press("ArrowRight" if steps_x > 0 else "ArrowLeft")
        for _ in range(abs(steps_y)):
            await page.keyboard.press("ArrowDown" if steps_y > 0 else "ArrowUp")
        log.info("CAPTCHA piece moved: %d horizontal, %d vertical steps",
                 steps_x, steps_y)
        await page.wait_for_timeout(300)

        # wait until "Next" becomes enabled and click it
        for _ in range(15):
            btn = frame.locator("button.btn-solid-purple")
            if await btn.count() > 0 and await btn.get_attribute("disabled") is None:
                await btn.click()
                log.info("CAPTCHA submitted")
                return True
            await asyncio.sleep(1)
        raise CaptchaError("CAPTCHA 'Next' button never became enabled")
