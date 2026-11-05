import sys
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

wordlist_path = sys.argv[1] if len(sys.argv) > 1 else "custom.txt"

with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
    for i, line in enumerate(f):
        pw = line.rstrip("\n")
        if not pw:
            continue
        try:
            kp = PyKeePass("infrastructure.kdbx", password=pw)
            print(f"\n[+] FOUND PASSWORD: {pw!r}")
            sys.exit(0)
        except CredentialsError:
            pass
        except Exception as ex:
            print(f"[!] unexpected error on {pw!r}: {ex}")
        if i % 50 == 0:
            print(f"  tried {i} ({pw!r})...", end="\r")

print("\n[-] not found in this wordlist")
