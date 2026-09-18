"""
Node.js PGP Worker — persistent subprocess for fast decrypt/keygen.

Instead of spawning a new Node.js process for every operation (~200-300ms),
keeps a single worker alive and communicates via stdin/stdout JSON lines (~5-10ms).

Usage:
    worker = CryptoWorker()
    plaintext = worker.decrypt(key_password, primary_key, body, address_key, token)
    key_data = worker.generate_key(email, key_password, primary_key)
    worker.stop()

Thread-safe: reentrant lock serializes request/response pairs.
Auto-restart: if the worker dies, the next call restarts it and retries once.
Timeouts: a reader thread feeds a queue, so a hung worker raises instead of
blocking forever.
"""

import json
import logging
import os
import queue
import shutil
import subprocess
import threading
from collections import deque

log = logging.getLogger(__name__)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKER_SCRIPT = os.path.join(SCRIPT_DIR, "decrypt", "worker.mjs")

# Which Node to run. $PROTON_NODE_BIN covers what PATH cannot: nvm/fnm shells
# that never exported it, Windows installs outside PATH, and systems where the
# binary is called "nodejs".
_NODE_NAMES = ("node", "nodejs")


def _resolve_node():
    """Return the Node executable to launch.

    Resolved with shutil.which rather than handed to Popen as a bare name:
    which expands %PATHEXT% on Windows, so an nvm/fnm `node.cmd` shim is found,
    while Popen(shell=False) would not run it. Falls back to the bare name so
    the FileNotFoundError (and its install hint) still surfaces at start().
    """
    override = os.environ.get("PROTON_NODE_BIN")
    if override:
        return shutil.which(override) or override
    for name in _NODE_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return _NODE_NAMES[0]

_EOF = object()  # sentinel pushed when the worker's stdout closes


class WorkerError(RuntimeError):
    """Raised when a crypto operation fails (e.g. wrong key, bad input)."""


class WorkerUnavailable(WorkerError):
    """Raised when the worker process itself is broken.

    Distinct from WorkerError so callers that try many keys in a loop can
    bail out immediately instead of retrying against a dead worker.
    """


class CryptoWorker:
    """Persistent Node.js worker for PGP operations."""

    def __init__(self, auto_start=True, start_timeout=30):
        self._proc = None
        # RLock (not Lock): _request holds the lock and may call start()
        # through _ensure_alive(), which needs to re-acquire it.
        self._lock = threading.RLock()
        self._stdout_q = queue.Queue()
        self._stderr_tail = deque(maxlen=20)
        self._readers = []
        self._start_timeout = start_timeout
        if auto_start:
            self.start()

    # ── process lifecycle ────────────────────────────────────────────

    def _pump_stdout(self, proc, q):
        """Feed stdout lines into the queue. Ends with an _EOF sentinel."""
        try:
            for line in proc.stdout:
                q.put(line)
        except (OSError, ValueError) as e:
            # Pipe closed under us (worker killed) — the _EOF sentinel below is
            # what the requester waits on.
            log.debug("stdout pump ended: %s", e)
        finally:
            q.put(_EOF)

    def _pump_stderr(self, proc, tail):
        """Drain stderr so the pipe buffer never fills and blocks Node."""
        try:
            for line in proc.stderr:
                tail.append(line.rstrip("\n"))
        except (OSError, ValueError) as e:
            log.debug("stderr pump ended: %s", e)

    def start(self):
        """Start the Node.js worker process (no-op if already running)."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return

            self._stdout_q = queue.Queue()
            self._stderr_tail = deque(maxlen=20)

            try:
                proc = subprocess.Popen(
                    [_resolve_node(), WORKER_SCRIPT],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    # The worker writes UTF-8 JSON. Without pinning it, text
                    # mode decodes with the platform's preferred encoding
                    # (cp1252 on Windows), which mangles every non-ASCII mail
                    # body. errors="replace" keeps a damaged byte from killing
                    # the reader thread outright.
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,  # line buffered
                )
            except FileNotFoundError:
                raise WorkerUnavailable(
                    "Node.js not found. proton-mail-api requires Node.js >= 18 "
                    "for PGP operations. Install it and ensure `node` is on "
                    "PATH, or point $PROTON_NODE_BIN at the executable."
                )

            self._proc = proc
            self._readers = [
                threading.Thread(
                    target=self._pump_stdout, args=(proc, self._stdout_q), daemon=True
                ),
                threading.Thread(
                    target=self._pump_stderr, args=(proc, self._stderr_tail), daemon=True
                ),
            ]
            for t in self._readers:
                t.start()

            # Wait for the "worker ready" handshake.
            try:
                line = self._stdout_q.get(timeout=self._start_timeout)
            except queue.Empty:
                self._kill()
                raise WorkerUnavailable(
                    f"Crypto worker did not start within {self._start_timeout}s"
                )
            if line is _EOF:
                err = self._stderr_text()
                self._kill()
                raise WorkerUnavailable(f"Crypto worker exited on startup. {err}")
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                self._kill()
                raise WorkerUnavailable(
                    f"Crypto worker sent invalid handshake: {line[:200]!r}"
                )
            if not (resp.get("ok") and resp.get("data") == "worker ready"):
                self._kill()
                raise WorkerUnavailable(f"Crypto worker handshake failed: {resp}")

    def _stderr_text(self):
        if not self._stderr_tail:
            return ""
        return "stderr: " + " | ".join(self._stderr_tail)

    def _kill(self):
        """Force kill the worker and reset state.

        Teardown must never raise: it runs from error paths and __del__. Each
        step is tolerated individually so a closed pipe cannot leave the process
        unreaped.
        """
        proc = self._proc
        self._proc = None
        self._readers = []
        if proc is None:
            return
        try:
            proc.kill()
        except OSError as e:
            log.debug("worker kill failed: %s", e)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            log.warning("crypto worker did not exit after kill")
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except OSError as e:
                log.debug("worker stream close failed: %s", e)

    def _ensure_alive(self):
        """Restart the worker if it is not running."""
        if self._proc is None or self._proc.poll() is not None:
            self._kill()
            self.start()

    def _drain_queue(self):
        """Discard stale responses left over from a timed-out request."""
        while True:
            try:
                self._stdout_q.get_nowait()
            except queue.Empty:
                return

    # ── request/response ─────────────────────────────────────────────

    def _request(self, req, timeout=60, _retry=True):
        """Send a request and return the parsed response. Thread-safe."""
        with self._lock:
            restarted = False
            if self._proc is None or self._proc.poll() is not None:
                self._ensure_alive()
                restarted = True

            if not restarted:
                # Only stale data from a previous timeout can be pending here;
                # a fresh worker's handshake was already consumed by start().
                self._drain_queue()

            proc = self._proc
            if proc is None or proc.stdin is None:
                raise WorkerUnavailable("Crypto worker is not running")

            try:
                proc.stdin.write(json.dumps(req) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError, AttributeError, ValueError) as e:
                self._kill()
                if _retry:
                    return self._request(req, timeout=timeout, _retry=False)
                raise WorkerUnavailable(f"Crypto worker write failed: {e}")

            try:
                line = self._stdout_q.get(timeout=timeout)
            except queue.Empty:
                # Worker is hung — kill it so the next call gets a clean one.
                self._kill()
                raise WorkerUnavailable(
                    f"Crypto worker timed out after {timeout}s (type={req.get('type')})"
                )

            if line is _EOF:
                err = self._stderr_text()
                self._kill()
                if _retry:
                    return self._request(req, timeout=timeout, _retry=False)
                raise WorkerUnavailable(f"Crypto worker died mid-request. {err}")

            try:
                return json.loads(line)
            except json.JSONDecodeError:
                raise WorkerUnavailable(
                    f"Crypto worker sent invalid JSON: {line[:200]!r}"
                )

    # ── public API ───────────────────────────────────────────────────

    def ping(self):
        """Check that the worker responds."""
        resp = self._request({"type": "ping"}, timeout=15)
        return resp.get("ok", False)

    def decrypt(self, key_password, primary_key, body, address_key=None, token=None,
                timeout=60):
        """Decrypt a PGP-encrypted mail body.

        Args:
            key_password: bcrypt-derived key password
            primary_key: PGP primary private key (armored)
            body: PGP-encrypted message (armored)
            address_key: Address PGP private key (armored, optional)
            token: Encrypted token for the address key (armored, optional)

        Returns:
            str: Decrypted plaintext body

        Raises:
            WorkerError: If decrypt fails or the worker is unavailable.
        """
        req = {
            "type": "decrypt",
            "key_password": key_password,
            "primary_key": primary_key,
            "body": body,
        }
        if address_key:
            req["address_key"] = address_key
        if token:
            req["token"] = token

        resp = self._request(req, timeout=timeout)
        if resp.get("ok"):
            return resp["data"]
        raise WorkerError(f"Decrypt failed: {resp.get('error', 'unknown')}")

    def generate_key(self, email, key_password, primary_key, timeout=60):
        """Generate a new PGP address key.

        Returns:
            dict: {private_key, token, signed_key_list, signature, fingerprint}

        Raises:
            WorkerError: If key generation fails.
        """
        req = {
            "type": "generate_key",
            "email": email,
            "key_password": key_password,
            "primary_key": primary_key,
        }
        resp = self._request(req, timeout=timeout)
        if resp.get("ok"):
            return resp["data"]
        raise WorkerError(f"Key generation failed: {resp.get('error', 'unknown')}")

    def stop(self):
        """Gracefully stop the worker: ask it to exit, then force kill."""
        with self._lock:
            proc = self._proc
            if proc is not None and proc.poll() is None and proc.stdin is not None:
                try:
                    proc.stdin.write(json.dumps({"type": "exit"}) + "\n")
                    proc.stdin.flush()
                    proc.wait(timeout=5)
                except (OSError, ValueError) as e:
                    log.debug("graceful worker exit failed: %s", e)
                except subprocess.TimeoutExpired:
                    log.warning("crypto worker ignored exit request; killing")
            self._kill()

    @property
    def is_alive(self):
        return self._proc is not None and self._proc.poll() is None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def __del__(self):
        # Interpreter shutdown can pull modules out from under us (module globals
        # become None), so this must swallow everything — a raise here is printed
        # and ignored anyway.
        try:
            self._kill()
        except BaseException:  # noqa: BLE001, S110 — teardown must never raise
            pass


# ── module-level singleton ───────────────────────────────────────────

_global_worker = None
_global_lock = threading.Lock()


def get_worker():
    """Get or create the shared crypto worker."""
    global _global_worker
    with _global_lock:
        if _global_worker is None:
            _global_worker = CryptoWorker()
        return _global_worker


def stop_worker():
    """Stop the shared crypto worker."""
    global _global_worker
    with _global_lock:
        if _global_worker is not None:
            _global_worker.stop()
            _global_worker = None
