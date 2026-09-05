# RideSafe

Secure ride-sharing and carpool coordination app — CSE447 project.

RideSafe encrypts all sensitive data (rider/driver profiles, trip requests,
trip logs, and in-app chat messages) before storing it, and decrypts it only
for authorized users. Only asymmetric encryption is used throughout — RSA
and ECC (ECIES), both implemented from scratch — along with HMAC/CBC-MAC
for tamper detection and HOTP/TOTP for two-factor authentication.

## Features

- Registration & login with salted, hashed passwords
- Two-factor authentication
- Key generation, storage, and rotation
- Encrypted ride requests and trip logs
- Encrypted in-app chat between rider and driver
- Encrypted profile data
- Role-based access control (rider / driver / admin)
- Secure session management

## Tech stack

- Backend: Flask (Python)
- Database: Supabase (Postgres)
- Frontend: HTML/CSS with Jinja2 templates

## Local setup

1. Clone the repo and set up a virtual environment:
   ```bash
   git clone <repo-url>
   cd ridesafe
   python -m venv venv
   venv\Scripts\activate   # Windows
   # source venv/bin/activate   # Mac/Linux
   pip install -r requirements.txt
   ```

2. Create a Supabase project, then run `supabase/schema.sql` in the SQL
   Editor to set up the database tables.

3. Copy `.env.example` to `.env` and fill in your Supabase credentials.

4. Run the app:
   ```bash
   python app.py
   ```
   Visit `http://localhost:5001`.

## Project structure

```
app.py           - entry point, registers all routes
config.py        - environment/config loading
crypto/          - RSA, ECC, HMAC, and OTP implementations
routes/          - auth, profile, keys, trips, chat, sessions, admin
templates/       - HTML pages
static/          - CSS
supabase/        - database schema
```

## Branching

All work happens on feature branches, merged into `main` via pull request.
