"""
proton-mail-api — Proton Mail HTTP API client with PGP decrypt.

Usage:
    from proton_mail_api import ProtonMailClient

    client = ProtonMailClient("my_account.json")
    msgs = client.inbox(size=10)
    body = client.read(msgs["messages"][0]["id"])
    code = client.wait_code(to_filter="myaddr@proton.me", from_filter="github")
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .crypto_worker import CryptoWorker, get_worker, stop_worker
from .reader import HumanVerificationRequired, ProtonMailClient, ProtonReader

try:
    __version__ = _pkg_version("proton-mail-api")
except PackageNotFoundError:  # imported from the working tree (no install)
    __version__ = "0.0.0.dev0"

__all__ = [
    "CryptoWorker",
    "HumanVerificationRequired",
    "ProtonMailClient",
    "ProtonReader",
    "get_worker",
    "stop_worker",
]
