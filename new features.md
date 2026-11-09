# THE-GUARDIAN – Five feature additions

## Implemented backend endpoints

### Savings goals
- `GET /api/v1/user/savings-goals`
- `POST /api/v1/user/savings-goals`
- `POST /api/v1/user/savings-goals/{goal_id}/contribute`

Contributions debit the user's Guardian wallet and create wallet-ledger entries. Goals are completed automatically when the target is reached.

### QR payments
- `GET /api/v1/user/qr-code`
- `POST /api/v1/user/qr-pay`

QR payment transfers funds between two active Guardian accounts and records matching debit/credit ledger entries. This is an internal Guardian wallet payment, not an Airtel or bank QR network payment.

### Virtual Guardian Card
- `GET /api/v1/user/virtual-card`
- `POST /api/v1/user/virtual-card/freeze`
- `POST /api/v1/user/virtual-card/unfreeze`

This is a simulated in-app card record. It is not a bank-issued card and has no external card-network capability.

### Spending analytics
- `GET /api/v1/user/spending-analytics?period=week|month|year`

Summarizes allowed outgoing transactions from the user's transaction history.

### Security centre
- `GET /api/v1/user/security-alerts`
- `POST /api/v1/user/security-alerts/{alert_id}/read`
- `GET /api/v1/admin/security-alerts`
- `GET /api/v1/admin/feature-overview`

The customer UI shows security alerts and the admin UI shows feature counts and security alerts. Alerts are currently generated for virtual-card freeze/unfreeze actions; transaction-risk alert automation can be expanded in a subsequent pass.

## Installation

Replace the corresponding files in your project with the versions in this archive. Keep your existing `.env` and database file. The new SQLAlchemy tables are created by the existing `Base.metadata.create_all()` startup initialization; existing tables are not dropped.

Install dependencies from the project's existing `requirements.txt`, then restart the FastAPI application. Back up the database before deploying any schema changes.

## Important limitations

- QR payments work only between active THE-GUARDIAN accounts.
- The virtual card is simulated and cannot be used with Visa/Mastercard or merchants.
- Existing wallet top-up, withdrawal, Airtel and airtime routes remain subject to their current simulation/provider integrations.
- Production deployment should add database transaction locking/idempotency, CSRF protection, rate limiting, audit review, and a real card/payment provider before handling real funds.
