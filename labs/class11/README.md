# CSRF Lab Report (NotesApp Flaw #11)

**Environment**: Windows / PowerShell / Docker

## 1. Break (CSRF Exploit)
**Status**: Vulnerable. Server accepted POST without a CSRF token.

- **Forged Request (No Token)**: `HTTP 302` (Accepted)
- **Result**: Eve's grade (note_id: 10) was successfully changed to `20.0` via curl, and `19.5` via `prize.html`.

> **Screenshot: Terminal Forge Success**
> ![Part 1 Forge](./images/part1_forge_success.png)

> **Screenshot: Browser Exploit Success**
> ![Part 2 Browser](./images/part2_browser_exploit.png)

---

## 2. Fix (Remediation)

### `web/app.py`
```python
import secrets
import hmac

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def check_csrf():
    if request.method == "POST" and request.endpoint != "login":
        expected = session.get("csrf")
        sent = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "CSRF token missing or wrong")
```

### Templates (`teacher.html`, `admin.html`)
Added to all `<form method="post">`:
```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

---

## 3. Proof of Fix (Verification)

- **Forged Request (No Token)**: `HTTP 400 Bad Request` (Rejected)
- **Real Form (With Token)**: `HTTP 302` (Success)

> **Screenshot: Terminal Verification**
> ![Part 4 Verification](./images/part4_verification.png)