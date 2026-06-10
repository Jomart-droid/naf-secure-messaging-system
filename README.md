# NAF Secure Messaging System

A Flask-based secure signal and internal messaging platform for structured unit communication workflows. This repository is prepared as a sanitized portfolio/demo version. Runtime files, local databases, uploaded documents, generated PDFs, backups, logs, and private environment secrets are intentionally excluded.

## Key Features

- Secure login with role-based access control
- Unit, officer, commander, and admin workflows
- Signal/broadcast drafting, review, release, recall, and acknowledgement tracking
- Direct messaging and real-time notifications with Flask-SocketIO
- PDF print/export workflow with watermark and password-protected exports
- Audit logging, session controls, and security checks
- NAF unit import support through CSV seed data
- Dark/light responsive dashboard UI

## Tech Stack

- Python / Flask
- Flask-Login
- Flask-SQLAlchemy
- Flask-SocketIO
- Flask-WTF / CSRF protection
- ReportLab and pypdf for PDF generation/protection
- SQLite for local demo, PostgreSQL-ready through `DATABASE_URL`

## Repository Safety Notes

The following are not included and should never be committed to GitHub:

- `.env` files
- Local SQLite databases
- `instance/` runtime data
- Uploaded documents/signatures
- Generated PDFs and signal bank exports
- Backup zip files
- Logs
- Real user, unit, service, or operational records

Use `.env.example` as the template and generate local secrets with the bootstrap script.

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
```

Windows:

```bash
.\.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Create local environment variables

```bash
python scripts/bootstrap_env.py
```

This creates a local `.env` file with secure random keys. Do not commit the generated `.env`.

### 4. Run the app

```bash
python run.py
```

Open:

```text
http://127.0.0.1:5000/setup
```

Then create the first admin account and log in.

## Optional: Import Units

```bash
flask import-naf-units
```

or:

```bash
python scripts/import_naf_units.py
```

## Health Check

```text
http://127.0.0.1:5000/api/health
```

## Local Demo Password Reset

For local/demo databases only:

```bash
python scripts/reset_demo_passwords.py "NewStrongPassword123!"
```

## Suggested GitHub Repository Name

```text
naf-secure-messaging-system
```

## Author

Josiah Ukandu Martins
