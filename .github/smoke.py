"""Cross-platform smoke test — no network, no Proton account.

The unit tests simulate Windows by deleting os.fchmod and pointing TMPDIR
elsewhere. This runs the real paths on the real OS instead:

  1. Node is discovered on this platform (PATHEXT on Windows, PATH elsewhere).
  2. The worker handshake completes, and the pipe survives non-ASCII.
  3. A config round-trips through the atomic save with whatever permissions
     the OS actually grants.
  4. Diagnostics land in this platform's temp directory.

Exits non-zero on the first failure so CI goes red with a readable message.
"""

import json
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proton_mail_api import ProtonMailClient
from proton_mail_api.captcha import PuzzleSolver
from proton_mail_api.crypto_worker import (
    _resolve_node,
    get_worker,
    stop_worker,
)

failures = []


def check(label, condition, detail=""):
    status = "ok  " if condition else "FAIL"
    print(f"  {status} {label}{f'  {detail}' if detail else ''}")
    if not condition:
        failures.append(label)


_FIXTURE_JS = """
import * as openpgp from "openpgp";
const plain = process.argv[2];
const { privateKey } = await openpgp.generateKey({
  userIDs: [{ email: "smoke@proton.me" }], passphrase: "pw",
  format: "armored" });
const key = await openpgp.decryptKey({
  privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
  passphrase: "pw" });
const enc = await openpgp.encrypt({
  message: await openpgp.createMessage({ text: plain }),
  encryptionKeys: key.toPublic() });
process.stdout.write(JSON.stringify([privateKey, enc]));
"""


def _make_encrypted_fixture(plain):
    """Generate a key and encrypt `plain` to it, using the bundled openpgp.

    Returns (armoured_private_key, ciphertext), or None when the vendored
    node_modules is absent -- a source checkout without `npm install`.
    """
    import subprocess

    decrypt_dir = (pathlib.Path(__file__).resolve().parents[1]
                   / "proton_mail_api" / "decrypt")
    if not (decrypt_dir / "node_modules" / "openpgp").is_dir():
        return None

    script = decrypt_dir / "_smoke_fixture.mjs"
    script.write_text(_FIXTURE_JS)
    try:
        result = subprocess.run(
            [_resolve_node(), script.name, plain],
            cwd=decrypt_dir, capture_output=True, text=True,
            encoding="utf-8", timeout=120, check=False,
        )
    finally:
        script.unlink(missing_ok=True)

    if result.returncode != 0:
        print(f"  note: fixture generation failed: {result.stderr[-200:]}")
        return None
    return tuple(json.loads(result.stdout))


print("== node discovery ==")
node = _resolve_node()
check("node resolved to a real path", os.path.isabs(node), node)

print("== worker handshake ==")
worker = get_worker()
try:
    check("ping answered", worker.ping() is True)

    from proton_mail_api.crypto_worker import WorkerError
    try:
        worker.decrypt(
            key_password="pw",
            primary_key="-----BEGIN PGP PRIVATE KEY BLOCK-----\nnope\n",
            body="not-a-message",
        )
        check("bad key rejected", False, "no error raised")
    except WorkerError as e:
        check("bad key rejected", True, type(e).__name__)

    # Pipe encoding, proved end to end. A key is generated, non-ASCII text is
    # encrypted to it, and the worker decrypts it back. Checking the error text
    # instead would prove nothing: those messages are ASCII, so they survive a
    # cp1252 pipe unharmed. Only content that round-trips catches it -- on a
    # mis-encoded pipe this arrives as "DoÄŸrulama ... éªŒè¯".
    plain = "Dogrulama/Doğrulama 123456 验证码 인증번호"
    fixture = _make_encrypted_fixture(plain)
    if fixture is None:
        print("  skip non-ascii round trip (openpgp not installed)")
    else:
        private_key, ciphertext = fixture
        out = worker.decrypt(key_password="pw", primary_key=private_key,
                             body=ciphertext)
        check("non-ascii survives the worker pipe", out == plain,
              repr(out)[:60])
finally:
    stop_worker()

print("== config round trip ==")
with tempfile.TemporaryDirectory() as d:
    path = pathlib.Path(d) / "smoke_account.json"
    path.write_text(json.dumps({"email": "a@proton.me", "password": "pw"}))

    client = ProtonMailClient(str(path))
    try:
        client.config["uid"] = "smoke-uid"
        client.config["note"] = "non-ascii: Doğrulama 验证码"
        client._save_config()

        back = json.loads(path.read_text(encoding="utf-8"))
        check("uid persisted", back["uid"] == "smoke-uid")
        check("non-ascii survived", back["note"].endswith("验证码"))

        leftovers = list(pathlib.Path(d).glob(".proton-config-*"))
        check("no temp file left behind", leftovers == [], str(leftovers))

        if hasattr(os, "fchmod"):
            mode = path.stat().st_mode & 0o777
            check("owner-only permissions", mode == 0o600, oct(mode))
        else:
            print("  skip owner-only permissions (no os.fchmod on this OS)")
    finally:
        client.close()

print("== diagnostics location ==")
tmp = tempfile.gettempdir()
for name, value in (("DEBUG_BG", PuzzleSolver.DEBUG_BG),
                    ("DEBUG_MARKED", PuzzleSolver.DEBUG_MARKED)):
    check(f"{name} is under the platform temp dir",
          value.startswith(tmp), value)

print()
if failures:
    print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}")
    raise SystemExit(1)
print("all checks passed")
