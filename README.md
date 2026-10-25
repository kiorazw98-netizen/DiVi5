# PocketPay
About the Project

PayFlow is a simulated digital wallet project built to practise software development. It demonstrates a wallet dashboard and payment-system concepts without transferring real money.

Live Demo

Add your Render website link here.

Source Code

https://github.com/kiorazw98-netizen/DiVi5

Technologies Used
Python
FastAPI
HTML
CSS
Key Features
Digital wallet dashboard
Simulated wallet balance
Payment simulation
User-friendly interface
Purpose

To develop my skills in backend programming, web development, and fintech application design.

PocketPay is a wallet demonstration with a responsive browser UI, REST API, SQLite persistence, password-based login, user/admin permissions, multiple ZAR wallets, invoices, transaction messages, activity analytics, digital receipts, and an administrator audit log. Internal transfers are simulated. Optional Stripe Checkout top-ups charge a real payment method and credit the local wallet after a signed webhook confirms payment; this demo does not provide withdrawals or bank transfers.

## Run locally

Requires Python 3.10 or newer.

```powershell
cd "C:\Users\uknown\OneDrive\Documents\DiVi 5"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

Open <http://127.0.0.1:8000>. The interactive REST API documentation is at <http://127.0.0.1:8000/docs>.

### Demo accounts

| Role | Email | Password |
| --- | --- | --- |
| User | `alice@example.com` | `alice-demo-password` |
| User | `bob@example.com` | `bob-demo-password` |
| Admin | `admin@example.com` | `admin-demo-password` |

Wallets and invoices are denominated in South African rand (ZAR). Existing numeric balances are relabeled in ZAR without exchange-rate conversion. New accounts start with a zero-balance Main wallet. Demo accounts are inserted only when the database has no users. Their initial balances are R1,000 for Alice, R250 for Bob, and R0 for the administrator.

### Stripe top-ups

Top-ups are unavailable until Stripe is configured. Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` as server environment variables (never in source control), and set `PUBLIC_BASE_URL` to the publicly reachable HTTPS origin when deployed. Configure the Stripe webhook endpoint at `<PUBLIC_BASE_URL>/api/stripe/webhook` for `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`, and `checkout.session.expired`. The webhook signature is verified before any wallet is credited, and duplicate deliveries do not credit twice. Use Stripe test-mode credentials while developing; live payments require an eligible Stripe account, business compliance, HTTPS, and operational monitoring. The configured Stripe account must support ZAR presentment.

## REST API

- `POST /api/register` — create a user account and empty wallet.
- `POST /api/login` — sign in and receive a short-lived bearer token.
- `GET /api/me` — return the authenticated user and wallet balance.
- `POST /api/transfers` — submit a transfer with `recipient_email`, decimal `amount`, and a unique `idempotency_key`; optional `description`.
- `GET /api/wallets` / `POST /api/wallets` — list or create named ZAR wallets.
- `GET /api/transactions` — list transactions involving the authenticated user.
- `GET /api/transactions/{id}/messages` / `POST /api/transactions/{id}/messages` — read or send messages visible to transfer participants.
- `GET /api/transactions/{id}/receipt` — retrieve a receipt as a participant.
- `GET /api/invoices` / `POST /api/invoices` — list or create invoices for another user.
- `POST /api/invoices/{id}/pay` / `POST /api/invoices/{id}/cancel` — pay an invoice from a wallet or cancel an open invoice as its issuer.
- `GET /api/analytics` — summarize completed transfers and confirmed top-ups.
- `GET /api/topups/config` / `GET /api/topups` / `POST /api/topups/checkout` — check Stripe readiness, view top-ups, or start a Checkout session.
- `POST /api/stripe/webhook` — receive signed Stripe payment events.
- `GET /api/admin/audit` — read transaction audit events (admin role only).

Successful and insufficient-funds transfers end in `successful` and `failed` states, respectively. Each transfer records its `pending` creation event before the final state event. The idempotency key is unique per sender; repeating a matching request returns its existing transaction, while reusing the key with different transfer details returns `409 Conflict`. Amounts are stored as integer cents, and the debit, credit, and status updates run in one SQLite transaction.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Security and demo limitations

Passwords are stored as salted scrypt hashes. API access uses expiring HMAC-signed bearer tokens; the browser keeps its token in session storage. Users can see only their own transactions and receipts, and only administrators can read the audit log.

The project is not a production wallet or payment service. Stripe top-ups can charge real payment methods if live credentials are configured, but wallet accounting, invoices, and internal transfers are demonstration features; there are no withdrawals. Before any live deployment, configure persistent high-entropy `WALLET_SECRET` and Stripe secrets, use HTTPS, replace demo credentials and balances, add operational protections such as login throttling, reconciliation and backups, and obtain a security/compliance review. Without `WALLET_SECRET`, the app creates an ephemeral token-signing key at startup, so existing tokens stop working after a restart.
