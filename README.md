# TrustVault

Secure document sharing demo built with Flask + SQLite.

## Run

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Demo accounts

- Admin: admin@trustvault.local / Admin@123
- Owner: owner@trustvault.local / Owner@123
- Viewer: viewer@trustvault.local / Viewer@123
- Other viewer: other@trustvault.local / Viewer@456

Change these credentials and the Flask secret before production use.

## Security design

Files are stored in `private_files/` and are never served as public static files. Every download goes through `/documents/<id>/download`, which authenticates the user, checks document-level permission, writes an audit event, and only then returns the file.

Revocation deletes the permission row. Permission is checked on every request, so an old download route cannot remain valid.

## Roles

Admin: audit access and manage all documents.
Owner: manage owned documents and their permissions.
Viewer: access only explicitly granted documents.

## Tests

```bash
pytest -q
```

## Production notes

This is a seven-day challenge starter/demo, not a production-ready security product. For production, use Argon2/bcrypt password hashing, a production secret manager, HTTPS, object storage with private buckets, malware scanning, stronger audit integrity (append-only/WORM or hash chaining), CSRF protection where applicable, rate limiting, secure session cookies, and a managed database.
