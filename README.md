# Sales Dashboard — Login & Persistence

Run the dashboard:

```bash
pip install streamlit pandas openpyxl plotly bcrypt tomlkit extra-streamlit-components
python keys.py            # first time: creates cookie key in .streamlit/config.toml
python app.py             # serves http://127.0.0.1:8000 (open http://127.0.0.1:8000/login)
```

Self-service **Register** is on the login page; or seed a user with
`python keys.py <username> <name> <password>`.

Auth implementation notes (`app.py`, `keys.py`):
- Credentials live in `credentials.json`, located relative to `app.py`
  (`__file__`), never the current working directory. Passwords are bcrypt
  hashes only; registration merges by username under a file lock and writes
  through a temp file + atomic rename, so concurrent registrations never lose
  updates and an existing username is rejected (first password wins).
- The session cookie is HMAC-signed. Its name, signing key and expiry (fixed
  30-day absolute lifetime) are read solely from the `[auth]` table in
  `.streamlit/config.toml`; `keys.py` generates that key once and never
  rotates it, so a browser refresh keeps the session.
- Authentication runs before any xlsx access; `load_data()` is called and
  cached only after a successful login. A missing credential file is created
  empty on first use; a corrupted file is quarantined and the app degrades to
  a login prompt instead of crashing.

Tests: `python -m pytest -q` (`tests/test_auth_flow.py`).

---

# Add a User Authentication Service (Login Form) in Streamlit

# Add a User Authentication Service (Login Form) in Streamlit

In this video, I will show you how to add a user authentication service (login form) in Streamlit so that your users can log in and see the content of your streamlit app. To implement the user authentication, we will use the ‘streamlit-authenticator’ library, a secure authentication module to validate user credentials in a Streamlit application.

## Video Tutorial
[![YouTube Video](https://img.youtube.com/vi/JoFGrSRj4X4/0.jpg)](https://youtu.be/JoFGrSRj4X4)

## Demo Website
⭐ https://userauth-dashboard.herokuapp.com/

## Screenshot
![Login Screenshot](/demo.jpg?raw=true "Login Form")

## Streamlit-authenticator
⭐ Check out the library here: https://github.com/mkhorasani/Streamlit-Authenticator

## Learn Excel Automation with Python
If this repo helped you, my [Excel Automation Course](https://pythonandvba.com/excel-automation-course/) teaches the full workflow from zero: Python for Excel users, xlwings, pandas and real projects.

Also check out my other [tools and templates](https://pythonandvba.com/solutions).

## Connect with Me
- **YouTube:** [CodingIsFun](https://youtube.com/c/CodingIsFun)
- **Website:** [PythonAndVBA](https://pythonandvba.com)
- **LinkedIn:** [Sven Bosau](https://www.linkedin.com/in/sven-bosau/)
- **Contact:** [Get in Touch](https://pythonandvba.com/contact)
## Support
If you find this project helpful, consider buying me a coffee. 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://pythonandvba.com/coffee-donation)
