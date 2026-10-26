import hashlib, time
from argon2 import PasswordHasher

N = 100_000
t = time.time()
for _ in range(N):
    hashlib.md5(b"guess").hexdigest()
md5_rate = N / (time.time() - t)
print(f"MD5: {md5_rate:,.0f} guesses/second")

ph = PasswordHasher()
t = time.time()
ph.hash("guess")
one = time.time() - t
print(f"Argon2: {one*1000:.0f} ms for ONE guess ({1/one:.1f} guesses/second)")