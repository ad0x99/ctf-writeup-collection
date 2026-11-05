import sys
import multiprocessing as mp
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

DB = "infrastructure.kdbx"

def try_password(pw):
    try:
        PyKeePass(DB, password=pw)
        return pw
    except CredentialsError:
        return None
    except Exception:
        return None

def chunks(iterable, n):
    buf = []
    for item in iterable:
        buf.append(item)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf

def main(wordlist_path, nproc):
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.rstrip("\n") for line in f if line.strip()]
    print(f"[*] {len(words)} candidates, {nproc} workers")

    with mp.Pool(nproc) as pool:
        for i, result in enumerate(pool.imap_unordered(try_password, words, chunksize=50)):
            if result is not None:
                print(f"\n[+] FOUND PASSWORD: {result!r}")
                pool.terminate()
                return
            if i % 2000 == 0:
                print(f"  tried ~{i}/{len(words)}", end="\r")
    print("\n[-] not found in this wordlist")

if __name__ == "__main__":
    wordlist = sys.argv[1] if len(sys.argv) > 1 else "custom.txt"
    nproc = int(sys.argv[2]) if len(sys.argv) > 2 else mp.cpu_count()
    main(wordlist, nproc)
