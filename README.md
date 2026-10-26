# Secure POS & Customer Loyalty — PostgreSQL starter

This is a security-focused modular baseline for deploying a Flask POS to Render with PostgreSQL. It is **not yet a verified one-for-one conversion** of every route and screen in your original pasted SQLite application. Use it as the secure foundation; merge the remaining original features (customer registration/login, WhatsApp offer screens, PDF invoice styling, product CSV import/export, loyalty customer portal, and complete reports) only after checking each route and its access controls.

## 1. Render setup
1. Create a PostgreSQL database in Render.
2. Create a Web Service from this project ZIP/repository.
3. Add environment variables:
   - `DATABASE_URL`: Render PostgreSQL **Internal Database URL** (if not auto-wired)
   - `POS_SECRET_KEY`: long random secret; do not put it in source code
   - `INITIAL_SUPERADMIN_USERNAME`: your chosen username
   - `INITIAL_SUPERADMIN_PASSWORD`: a unique password of at least 12 characters
   - `RATELIMIT_STORAGE_URI`: for multi-instance production, use a shared Redis-compatible URL; the default in-memory limiter resets on restart and is not shared between instances.
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Do not commit `.env`, passwords, database URLs, or backups to Git.

`render.yaml` is an example blueprint; check the current plan/availability and connect the database before deploying.

## 2. Local test
Python 3.11+ recommended:
```
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# Android/Pydroid: install packages from requirements.txt if supported
pip install -r requirements.txt
set DATABASE_URL=postgresql://...   # Windows CMD; use a real test database
set POS_SECRET_KEY=replace-with-a-long-random-secret
set INITIAL_SUPERADMIN_USERNAME=superadmin
set INITIAL_SUPERADMIN_PASSWORD=use-a-unique-12-plus-character-password
python app.py
```
Use a separate test database, not production.

## 3. Critical security notes
- Do not use the old known default `superadmin / Admin@123`.
- CSRF applies to POST forms; all state-changing routes should use POST and include `{{ csrf_token() }}`.
- Secure cookies require HTTPS, which Render provides for deployed services.
- `business_id` is read from the authenticated session for business-level pages. Never trust a submitted business ID.
- All business-specific reads/writes must include `business_id = %s`.
- Billing is transactional and locks the product row before checking stock. An idempotency key blocks duplicate bills caused by repeat submissions.
- The limiter's default memory storage is only suitable for a single process/dev test. Configure shared Redis storage for multi-instance deployment.
- Audit logs should never store passwords, session cookies, tokens, or payment-card data.
- Before using with real customers, run tests for cross-business access, concurrent billing, role permissions, CSRF, login throttling, backup restore, and failure recovery.
- Add migrations (Alembic) before changing production schema. `CREATE TABLE IF NOT EXISTS` does not update existing tables.
- For production, use least-privilege database credentials, daily backups, monitoring, and periodic restore drills.
