import time
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

t0 = time.time()
try:
    PyKeePass("infrastructure.kdbx", password="not-the-real-password")
except CredentialsError:
    pass
print(f"one attempt took {time.time()-t0:.2f}s")
