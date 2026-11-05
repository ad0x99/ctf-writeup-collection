from pykeepass import PyKeePass

kp = PyKeePass("infrastructure.kdbx", password="[REDACTED-KDBX-PASSWORD]")
for e in kp.entries:
    print("Title:", e.title)
    print("Username:", e.username)
    print("Password:", e.password)
    print("URL:", e.url)
    print("Notes:", e.notes)
    print("---")
