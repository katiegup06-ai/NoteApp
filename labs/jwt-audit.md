# LOGIN FIX — NotesApp flaw #4 (auth) closed

Assignment: Lab — Fix the login: make the forged token useless

## Required audit

```text
LOGIN FIX — NotesApp flaw #4 (auth) closed
  Fix 1: verify_jwt rejects alg:none and pins the algorithm to HS256.
  Fix 2: JWT_SECRET is long and random, read from the environment, with no weak default.
  Proof: alg:none teacher token      -> unauthorized (HTTP 401)
         s3cr3t-signed teacher token -> unauthorized (HTTP 401)
         real alice login           -> works; Alice sees her own grades.
```

## Verification details

Both teacher test tokens used a payload with `user_id: 9999`, `username: attacker`, and `role: teacher`.

| Check | Endpoint or action | Observed result |
|---|---|---|
| Unsigned teacher token (`alg: none`) | `GET /api/notes/3` with a Bearer token | HTTP 401; `{"error":"unauthorized"}` |
| Teacher token signed with the old lab secret `s3cr3t` | `GET /api/notes/3` with a Bearer token | HTTP 401; `{"error":"unauthorized"}` |
| Real Alice login | Sign in as Alice in the browser | Dashboard loads and Alice can see her own grades |

The API checks were made against the local NotesApp at `http://localhost:8080`.

## Implementation and secret configuration

- The fixed `verify_jwt` in `web/app.py` requires JSON-object header and payload values, accepts only the exact algorithm `HS256`, and checks the HMAC-SHA256 signature using `hmac.compare_digest`.
- The application reads the required signing secret using `os.environ["JWT_SECRET"]`; there is no weak fallback.
- A 32-byte random secret was generated and stored in the local `.env` file, which Git ignores.
- `docker-compose.yml` passes the secret using `${JWT_SECRET:?Missing JWT_SECRET}`.
- In production, the secret should come from a secrets store and be injected into the environment; its real value must never be committed to source control.
