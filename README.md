# Sales Dashboard (Streamlit, login-gated)

Sales dashboard for the supermarket dataset, visible only after login.

## Run

```bash
python keys.py        # one-time: writes cookie_key into .streamlit/config.toml
python app.py         # starts Streamlit on http://127.0.0.1:8000
```

Open http://127.0.0.1:8000/login (the root URL works too). The first launch
auto-creates an empty `credentials.json`; use the **Register** tab to create an
account, then log in. Refreshing the page keeps you logged in until the cookie
expires; **Logout** clears the session.

## How authentication works

- `keys.py` generates the cookie signing key and stores it in the `[auth]`
  section of `.streamlit/config.toml` (it never rotates an existing key).
- `app.py` reads `cookie_name`, `cookie_key`, `cookie_expiry_days` and
  `credentials_file` from that same config, so signer and verifier always
  agree. The token is an HMAC-signed `username/iat/exp` payload.
- Credentials live in `credentials.json`: passwords are bcrypt hashes only,
  never plaintext. Registration merges by username under an OS file lock
  (`msvcrt` on Windows, `fcntl` elsewhere) and writes via a temp file plus
  atomic `os.replace`, so concurrent registrations cannot lose updates.
- A duplicate username is **rejected** on registration and the existing hash is
  preserved.
- A missing credentials file is auto-provisioned (empty store) on first start;
  a *corrupt* file degrades to a login/unavailable prompt instead of crashing.
- The xlsx is loaded only after authentication succeeds and is cached with
  `st.cache_data`.

## Trade-offs

- Cookie lifetime is fixed at 7 days (`cookie_expiry_days` in config.toml),
  with no sliding renewal: bounded exposure if a cookie is stolen, predictable
  re-login frequency.
- Duplicate usernames are rejected (never overwritten) to prevent account
  hijacking by name guessing.
- Missing credentials on first start auto-provision an empty store; corrupt
  credentials are surfaced and require administrator action.

## Tests

```bash
python -m pytest -q
```

`tests/test_auth_flow.py` covers: refresh keeps the login, duplicate
registration preserves the old user, corrupt credentials degrade without
loading data, first-run provisioning, and concurrent registrations with no
lost updates.
