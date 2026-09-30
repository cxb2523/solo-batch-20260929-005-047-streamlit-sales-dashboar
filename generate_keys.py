"""Legacy entry point kept for compatibility; the real bootstrap is keys.py.

Run `python keys.py` to create the cookie key in .streamlit/config.toml and
the empty credentials.json store, or
`python keys.py <username> <name> <password>` to seed a user (bcrypt-hashed).
"""

from keys import main

if __name__ == "__main__":
    main()
