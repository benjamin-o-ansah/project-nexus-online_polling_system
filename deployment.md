# Deployment (Production) — Online Polling System (Flask)

This document describes how to deploy the Online Polling System to production using Render (Web Service + Render Postgres).

---

## 1. Production Principles

- Run behind a production WSGI server (Gunicorn), not the Flask dev server.
- Use environment variables for all secrets and configuration.
- Use PostgreSQL in production (Render managed Postgres).
- Apply migrations during deployment.
- Enable structured logs and audit logging.
- Enforce JWT/RBAC for protected endpoints.

---

## 2. Runtime Requirements

- Python 3.12+
- PostgreSQL 14+ (Render managed Postgres recommended)
- Gunicorn as application server

---

## 3. Required Environment Variables

Set these in your Render Web Service environment:

### Core
- `DB` = PostgreSQL connection string (Render internal URL recommended)
- `FLASK_ENV` = `production`
- `LOG_LEVEL` = `INFO` (or `WARNING`)

### JWT
- `JWT_SECRET_KEY` = a long, random secret string

### Mail (OTP delivery)
- `MAIL_SERVER` = `smtp.gmail.com`
- `MAIL_PORT` = `587`
- `MAIL_USE_TLS` = `true`
- `MAIL_USERNAME` = your sender email
- `MAIL_PASSWORD` = your mail credential (for Gmail, use an App Password)
- `MAIL_DEFAULT_SENDER` = same as sender email

> Note: Render provides Postgres internal URLs for services in the same region; use the internal connection string for best reliability. :contentReference[oaicite:1]{index=1}

---

## 4. Production Commands

### Build Command
```bash
pip install -r requirements.txt
