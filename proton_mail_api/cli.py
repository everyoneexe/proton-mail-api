"""
proton-mail CLI — Command-line interface for Proton Mail API.

Usage:
    proton-mail --config account.json inbox
    proton-mail --config account.json read <msg_id>
    proton-mail --config account.json code --from github --timeout 120
    proton-mail --config account.json setup
"""

from .reader import main

if __name__ == "__main__":
    main()
