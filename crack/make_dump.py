import hashlib

accounts = {
    "liwei": "123456",
    "sofia": "iloveyou",
    "tomk":  "qwerty123",
    "aisha": "password1",
    "marie": "mariepw",        # not a dictionary word - a predictable pattern
    "raj":   "Gv7#pLm2!xQ",    # long and random
}
with open("crack/leaked_users.txt", "w") as f:
    for username, password in accounts.items():
        # store "username:md5(password)" - unsalted MD5, exactly like the bad app would
        f.write(f"{username}:{hashlib.md5(password.encode()).hexdigest()}\n")
print("wrote crack/leaked_users.txt")