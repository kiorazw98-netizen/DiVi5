from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest, urlopen

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("WALLET_DB", BASE_DIR / "wallet.db"))
TOKEN_SECRET = os.environ.get("WALLET_SECRET", secrets.token_urlsafe(32)).encode()
TOKEN_TTL_SECONDS = 8 * 60 * 60
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def format_cents(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


@contextmanager
def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", maxsplit=1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(actual, expected)


def issue_token(user_id: int) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": user_id, "exp": int(time.time()) + TOKEN_TTL_SECONDS}).encode()
    ).rstrip(b"=")
    signature = hmac.new(TOKEN_SECRET, payload, hashlib.sha256).digest()
    return f"{payload.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def read_token(token: str) -> int:
    try:
        payload_part, signature_part = token.split(".", maxsplit=1)
        payload = payload_part.encode()
        signature = base64.urlsafe_b64decode(signature_part + "=" * (-len(signature_part) % 4))
        expected = hmac.new(TOKEN_SECRET, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        content = json.loads(
            base64.urlsafe_b64decode(payload_part + "=" * (-len(payload_part) % 4))
        )
        if int(content["exp"]) <= int(time.time()):
            raise ValueError("expired token")
        return int(content["sub"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired login token") from exc


def audit(
    connection: sqlite3.Connection,
    action: str,
    transaction_id: str | None = None,
    actor_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        """INSERT INTO audit_logs
           (id, transaction_id, actor_id, action, details, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()),
            transaction_id,
            actor_id,
            action,
            json.dumps(details or {}, separators=(",", ":")),
            now_iso(),
        ),
    )


def initialize_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        legacy_wallets = False
        wallet_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'wallets'"
        ).fetchone()
        if wallet_table and "id" not in {
            row["name"] for row in connection.execute("PRAGMA table_info(wallets)")
        }:
            connection.execute("ALTER TABLE wallets RENAME TO wallets_legacy")
            legacy_wallets = True
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL DEFAULT 'Main wallet',
                balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
                currency TEXT NOT NULL DEFAULT 'ZAR',
                is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                currency TEXT NOT NULL DEFAULT 'ZAR',
                status TEXT NOT NULL CHECK (status IN ('pending', 'successful', 'failed')),
                idempotency_key TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                failure_reason TEXT,
                created_at TEXT NOT NULL,
                sender_wallet_id INTEGER REFERENCES wallets(id),
                recipient_wallet_id INTEGER REFERENCES wallets(id),
                UNIQUE (sender_id, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                transaction_id TEXT REFERENCES transactions(id),
                actor_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS invoices (
                id TEXT PRIMARY KEY,
                issuer_id INTEGER NOT NULL REFERENCES users(id),
                issuer_wallet_id INTEGER NOT NULL REFERENCES wallets(id),
                customer_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                currency TEXT NOT NULL DEFAULT 'ZAR',
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'paid', 'cancelled')),
                created_at TEXT NOT NULL,
                due_date TEXT,
                paid_transaction_id TEXT REFERENCES transactions(id)
            );
            CREATE TABLE IF NOT EXISTS transaction_messages (
                id TEXT PRIMARY KEY,
                transaction_id TEXT NOT NULL REFERENCES transactions(id),
                sender_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 1000),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stripe_topups (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                wallet_id INTEGER NOT NULL REFERENCES wallets(id),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                currency TEXT NOT NULL DEFAULT 'ZAR',
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'paid', 'failed')),
                stripe_session_id TEXT UNIQUE,
                created_at TEXT NOT NULL,
                paid_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_transactions_sender
                ON transactions(sender_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_transactions_recipient
                ON transactions(recipient_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_created_at
                ON audit_logs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_invoices_issuer
                ON invoices(issuer_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_invoices_customer
                ON invoices(customer_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_messages_transaction
                ON transaction_messages(transaction_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_topups_user
                ON stripe_topups(user_id, created_at DESC);
            """
        )
        if legacy_wallets:
            connection.execute(
                """INSERT INTO wallets (user_id, name, balance_cents, currency,
                                        is_default, created_at)
                   SELECT user_id, 'Main wallet', balance_cents, 'ZAR', 1, ?
                   FROM wallets_legacy""",
                (now_iso(),),
            )
            connection.execute("DROP TABLE wallets_legacy")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_user_name ON wallets(user_id, name)"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_default ON wallets(user_id) WHERE is_default = 1"
        )
        transaction_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(transactions)")
        }
        if "sender_wallet_id" not in transaction_columns:
            connection.execute(
                "ALTER TABLE transactions ADD COLUMN sender_wallet_id INTEGER REFERENCES wallets(id)"
            )
        if "recipient_wallet_id" not in transaction_columns:
            connection.execute(
                "ALTER TABLE transactions ADD COLUMN recipient_wallet_id INTEGER REFERENCES wallets(id)"
            )
        connection.execute(
            """UPDATE transactions
               SET sender_wallet_id = (SELECT id FROM wallets
                                       WHERE user_id = transactions.sender_id AND is_default = 1),
                   recipient_wallet_id = (SELECT id FROM wallets
                                          WHERE user_id = transactions.recipient_id AND is_default = 1)
               WHERE sender_wallet_id IS NULL OR recipient_wallet_id IS NULL"""
        )
        connection.execute("UPDATE wallets SET currency = 'ZAR'")
        connection.execute("UPDATE transactions SET currency = 'ZAR'")
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            demo_users = (
                ("alice@example.com", "alice-demo-password", "user", 100_000),
                ("bob@example.com", "bob-demo-password", "user", 25_000),
                ("admin@example.com", "admin-demo-password", "admin", 0),
            )
            for email, password, role, balance in demo_users:
                cursor = connection.execute(
                    "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (email, hash_password(password), role, now_iso()),
                )
                connection.execute(
                    """INSERT INTO wallets
                       (user_id, name, balance_cents, currency, is_default, created_at)
                       VALUES (?, 'Main wallet', ?, 'ZAR', 1, ?)""",
                    (cursor.lastrowid, balance, now_iso()),
                )


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_db()
    yield


app = FastAPI(
    title="PocketPay",
    description="Wallet demo with simulated transfers and optional real Stripe Checkout top-ups.",
    version="1.0.0",
    lifespan=lifespan,
)


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class TransferRequest(BaseModel):
    recipient_email: str = Field(min_length=3, max_length=254)
    amount: Decimal = Field(gt=0, max_digits=10, decimal_places=2)
    idempotency_key: str = Field(min_length=8, max_length=128)
    description: str = Field(default="", max_length=200)
    wallet_id: int | None = None


class WalletRequest(BaseModel):
    name: str = Field(min_length=2, max_length=40)


class InvoiceRequest(BaseModel):
    customer_email: str = Field(min_length=3, max_length=254)
    amount: Decimal = Field(gt=0, max_digits=10, decimal_places=2)
    description: str = Field(default="", max_length=200)
    wallet_id: int | None = None
    due_date: str | None = Field(default=None, max_length=10)


class MessageRequest(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


class InvoicePayRequest(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=128)
    wallet_id: int | None = None


class TopupRequest(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=10, decimal_places=2)
    wallet_id: int


def current_user(
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required")
    user_id = read_token(authorization[7:])
    with connect_db() as connection:
        user = connection.execute(
            """SELECT users.id, users.email, users.role, wallets.id AS wallet_id,
                      wallets.balance_cents, wallets.name AS wallet_name,
                      wallets.currency
               FROM users JOIN wallets ON wallets.user_id = users.id
               WHERE users.id = ? AND wallets.is_default = 1""",
            (user_id,),
        ).fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="Login required")
    return dict(user)


def require_admin(
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator permission required")
    return user


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(credentials: Credentials) -> dict[str, Any]:
    email = credentials.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    try:
        with connect_db() as connection:
            cursor = connection.execute(
                """INSERT INTO users (email, password_hash, role, created_at)
                   VALUES (?, ?, 'user', ?)""",
                (email, hash_password(credentials.password), now_iso()),
            )
            user_id = cursor.lastrowid
            connection.execute(
                """INSERT INTO wallets (user_id, name, currency, is_default, created_at)
                   VALUES (?, 'Main wallet', 'ZAR', 1, ?)""",
                (user_id, now_iso()),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with that email already exists") from exc
    return {"token": issue_token(user_id), "user": {"id": user_id, "email": email, "role": "user"}}


@app.post("/api/login")
def login(credentials: Credentials) -> dict[str, Any]:
    email = credentials.email.strip().lower()
    with connect_db() as connection:
        row = connection.execute(
            "SELECT id, email, password_hash, role FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    if row is None or not verify_password(credentials.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    return {
        "token": issue_token(row["id"]),
        "user": {"id": row["id"], "email": row["email"], "role": row["role"]},
    }


@app.get("/api/me")
def me(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "balance": format_cents(user["balance_cents"]),
        "currency": user["currency"],
        "wallet_id": user["wallet_id"],
        "wallet_name": user["wallet_name"],
    }


@app.get("/api/wallets")
def wallets(user: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT id, name, balance_cents, currency, is_default
               FROM wallets WHERE user_id = ? ORDER BY is_default DESC, id""",
            (user["id"],),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "balance": format_cents(row["balance_cents"]),
            "currency": row["currency"],
            "is_default": bool(row["is_default"]),
        }
        for row in rows
    ]


@app.post("/api/wallets", status_code=status.HTTP_201_CREATED)
def create_wallet(
    request: WalletRequest,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    name = request.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Wallet name cannot be empty")
    try:
        with connect_db() as connection:
            cursor = connection.execute(
                """INSERT INTO wallets (user_id, name, currency, is_default, created_at)
                   VALUES (?, ?, 'ZAR', 0, ?)""",
                (user["id"], name, now_iso()),
            )
            wallet_id = cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A wallet with that name already exists") from exc
    return {
        "id": wallet_id,
        "name": name,
        "balance": "0.00",
        "currency": "ZAR",
        "is_default": False,
    }


@app.get("/api/topups/config")
def topup_config() -> dict[str, bool]:
    return {
        "available": bool(
            os.environ.get("STRIPE_SECRET_KEY")
            and os.environ.get("STRIPE_WEBHOOK_SECRET")
        )
    }


@app.get("/api/topups")
def topups(user: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT stripe_topups.id, wallets.name AS wallet_name,
                      stripe_topups.amount_cents, stripe_topups.currency,
                      stripe_topups.status, stripe_topups.created_at, stripe_topups.paid_at
               FROM stripe_topups JOIN wallets ON wallets.id = stripe_topups.wallet_id
               WHERE stripe_topups.user_id = ?
               ORDER BY stripe_topups.created_at DESC LIMIT 100""",
            (user["id"],),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "wallet_name": row["wallet_name"],
            "amount": format_cents(row["amount_cents"]),
            "currency": row["currency"],
            "status": row["status"],
            "created_at": row["created_at"],
            "paid_at": row["paid_at"],
        }
        for row in rows
    ]


@app.post("/api/topups/checkout")
def create_topup_checkout(
    request: TopupRequest,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, str]:
    secret_key = os.environ.get("STRIPE_SECRET_KEY")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not secret_key or not webhook_secret:
        raise HTTPException(
            status_code=503,
            detail="Stripe top-ups are not configured. Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET.",
        )
    amount_cents = int(request.amount * 100)
    if amount_cents < 100:
        raise HTTPException(status_code=422, detail="Top-up amount must be at least R1.00")
    with connect_db() as connection:
        wallet = connection.execute(
            "SELECT id, name FROM wallets WHERE id = ? AND user_id = ?",
            (request.wallet_id, user["id"]),
        ).fetchone()
        if wallet is None:
            raise HTTPException(status_code=404, detail="Wallet not found")
        topup_id = str(uuid.uuid4())
        connection.execute(
            """INSERT INTO stripe_topups
               (id, user_id, wallet_id, amount_cents, currency, status, created_at)
               VALUES (?, ?, ?, ?, 'ZAR', 'pending', ?)""",
            (topup_id, user["id"], wallet["id"], amount_cents, now_iso()),
        )

    base_url = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    form = urlencode(
        {
            "mode": "payment",
            "success_url": f"{base_url}/?topup=success",
            "cancel_url": f"{base_url}/?topup=cancelled",
            "client_reference_id": topup_id,
            "customer_email": user["email"],
            "metadata[topup_id]": topup_id,
            "line_items[0][quantity]": "1",
            "line_items[0][price_data][currency]": "zar",
            "line_items[0][price_data][unit_amount]": str(amount_cents),
            "line_items[0][price_data][product_data][name]": "PocketPay wallet top-up",
            "line_items[0][price_data][product_data][description]": f"Add funds to {wallet['name']}",
        }
    ).encode()
    stripe_request = UrlRequest(
        "https://api.stripe.com/v1/checkout/sessions",
        data=form,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": topup_id,
        },
        method="POST",
    )
    try:
        with urlopen(stripe_request, timeout=15) as response:
            stripe_session = json.loads(response.read())
    except HTTPError as exc:
        with connect_db() as connection:
            connection.execute(
                "UPDATE stripe_topups SET status = 'failed' WHERE id = ? AND status = 'pending'",
                (topup_id,),
            )
        raise HTTPException(
            status_code=502,
            detail="Stripe could not start checkout. Please try again later.",
        ) from exc
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Stripe checkout status is uncertain. Check your top-up history before retrying.",
        ) from exc
    session_id = stripe_session.get("id")
    checkout_url = stripe_session.get("url")
    if not isinstance(session_id, str) or not isinstance(checkout_url, str):
        with connect_db() as connection:
            connection.execute(
                "UPDATE stripe_topups SET status = 'failed' WHERE id = ? AND status = 'pending'",
                (topup_id,),
            )
        raise HTTPException(status_code=502, detail="Stripe returned an invalid checkout session")
    with connect_db() as connection:
        connection.execute(
            "UPDATE stripe_topups SET stripe_session_id = ? WHERE id = ?",
            (session_id, topup_id),
        )
    return {"checkout_url": checkout_url, "topup_id": topup_id}


@app.post("/api/stripe/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: Annotated[str | None, Header()] = None,
) -> dict[str, bool]:
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(status_code=503, detail="Stripe webhook is not configured")
    if not stripe_signature:
        raise HTTPException(status_code=400, detail="Missing Stripe signature")
    payload = await request.body()
    try:
        signature_parts = dict(
            item.split("=", 1) for item in stripe_signature.split(",") if "=" in item
        )
        timestamp = int(signature_parts["t"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature") from exc
    if abs(int(time.time()) - timestamp) > 300:
        raise HTTPException(status_code=400, detail="Expired Stripe signature")
    signed_payload = str(timestamp).encode() + b"." + payload
    expected_signature = hmac.new(
        webhook_secret.encode(), signed_payload, hashlib.sha256
    ).hexdigest()
    supplied_signatures = [
        part.split("=", 1)[1]
        for part in stripe_signature.split(",")
        if part.startswith("v1=")
    ]
    if not any(
        hmac.compare_digest(expected_signature, supplied)
        for supplied in supplied_signatures
    ):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    try:
        event = json.loads(payload)
        event_type = event["type"]
        checkout = event["data"]["object"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe event payload") from exc
    if event_type not in {
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
        "checkout.session.async_payment_failed",
        "checkout.session.expired",
    }:
        return {"received": True}
    metadata = checkout.get("metadata") or {}
    topup_id = metadata.get("topup_id")
    if not isinstance(topup_id, str):
        raise HTTPException(status_code=400, detail="Stripe event is missing top-up metadata")
    with connect_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        topup = connection.execute(
            "SELECT * FROM stripe_topups WHERE id = ?",
            (topup_id,),
        ).fetchone()
        if topup is None or (
            topup["stripe_session_id"] is not None
            and topup["stripe_session_id"] != checkout.get("id")
        ):
            raise HTTPException(status_code=404, detail="Top-up checkout not found")
        if topup["stripe_session_id"] is None:
            connection.execute(
                "UPDATE stripe_topups SET stripe_session_id = ? WHERE id = ?",
                (checkout.get("id"), topup_id),
            )
        if event_type in {
            "checkout.session.async_payment_failed",
            "checkout.session.expired",
        }:
            connection.execute(
                "UPDATE stripe_topups SET status = 'failed' WHERE id = ? AND status = 'pending'",
                (topup_id,),
            )
        elif (
            event_type == "checkout.session.completed"
            and checkout.get("payment_status") != "paid"
        ):
            return {"received": True}
        elif (
            checkout.get("payment_status") == "paid"
            and checkout.get("mode") == "payment"
            and checkout.get("currency") == "zar"
            and checkout.get("amount_total") == topup["amount_cents"]
        ):
            if topup["status"] == "pending":
                paid_at = now_iso()
                connection.execute(
                    "UPDATE wallets SET balance_cents = balance_cents + ? WHERE id = ?",
                    (topup["amount_cents"], topup["wallet_id"]),
                )
                connection.execute(
                    """UPDATE stripe_topups SET status = 'paid', paid_at = ?
                       WHERE id = ? AND status = 'pending'""",
                    (paid_at, topup_id),
                )
                audit(
                    connection,
                    "wallet.topup.paid",
                    actor_id=topup["user_id"],
                    details={"topup_id": topup_id, "amount_cents": topup["amount_cents"]},
                )
        else:
            raise HTTPException(status_code=400, detail="Stripe payment details do not match top-up")
    return {"received": True}


def settle_transfer(transaction_id: str) -> None:
    with connect_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        transaction = connection.execute(
            """SELECT sender_id, recipient_id, sender_wallet_id, recipient_wallet_id,
                      amount_cents, status
               FROM transactions WHERE id = ?""",
            (transaction_id,),
        ).fetchone()
        if transaction is None or transaction["status"] != "pending":
            return

        sender_wallet = connection.execute(
            "SELECT balance_cents FROM wallets WHERE id = ? AND user_id = ?",
            (transaction["sender_wallet_id"], transaction["sender_id"]),
        ).fetchone()
        if sender_wallet is None:
            raise RuntimeError(f"Source wallet missing for transaction {transaction_id}")
        if sender_wallet["balance_cents"] < transaction["amount_cents"]:
            connection.execute(
                "UPDATE transactions SET status = 'failed', failure_reason = ? WHERE id = ?",
                ("Insufficient balance", transaction_id),
            )
            audit(
                connection,
                "transfer.failed",
                transaction_id,
                transaction["sender_id"],
                {"reason": "insufficient_balance"},
            )
            return

        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents - ? WHERE id = ?",
            (transaction["amount_cents"], transaction["sender_wallet_id"]),
        )
        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents + ? WHERE id = ?",
            (transaction["amount_cents"], transaction["recipient_wallet_id"]),
        )
        connection.execute(
            "UPDATE transactions SET status = 'successful' WHERE id = ?",
            (transaction_id,),
        )
        audit(connection, "transfer.successful", transaction_id, transaction["sender_id"])


def transaction_response(row: sqlite3.Row, user_id: int) -> dict[str, Any]:
    return {
        "id": row["id"],
        "sender_id": row["sender_id"],
        "recipient_id": row["recipient_id"],
        "sender_email": row["sender_email"],
        "recipient_email": row["recipient_email"],
        "amount": format_cents(row["amount_cents"]),
        "currency": row["currency"],
        "status": row["status"],
        "description": row["description"],
        "failure_reason": row["failure_reason"],
        "created_at": row["created_at"],
        "direction": "sent" if row["sender_id"] == user_id else "received",
        "sender_wallet_name": row["sender_wallet_name"],
        "recipient_wallet_name": row["recipient_wallet_name"],
    }


@app.post("/api/transfers", status_code=status.HTTP_201_CREATED)
def transfer(
    request: TransferRequest,
    background_tasks: BackgroundTasks,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    recipient_email = request.recipient_email.strip().lower()
    description = request.description.strip()
    sender_id = user["id"]
    amount_cents = int(request.amount * 100)
    if amount_cents <= 0:
        raise HTTPException(status_code=422, detail="Amount must be at least 0.01")

    with connect_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        previous = connection.execute(
            """SELECT t.*, s.email AS sender_email, r.email AS recipient_email,
                      sw.name AS sender_wallet_name, rw.name AS recipient_wallet_name
               FROM transactions t
               JOIN users s ON s.id = t.sender_id
               JOIN users r ON r.id = t.recipient_id
               LEFT JOIN wallets sw ON sw.id = t.sender_wallet_id
               LEFT JOIN wallets rw ON rw.id = t.recipient_wallet_id
               WHERE t.sender_id = ? AND t.idempotency_key = ?""",
            (sender_id, request.idempotency_key),
        ).fetchone()
        sender_wallet = connection.execute(
            """SELECT id, balance_cents FROM wallets
               WHERE user_id = ? AND id = ?""",
            (sender_id, request.wallet_id or user["wallet_id"]),
        ).fetchone()
        if sender_wallet is None:
            raise HTTPException(status_code=404, detail="Source wallet not found")
        if previous:
            if (
                previous["recipient_email"].lower() != recipient_email
                or previous["amount_cents"] != amount_cents
                or previous["description"] != description
                or previous["sender_wallet_id"] != sender_wallet["id"]
            ):
                raise HTTPException(
                    status_code=409,
                    detail="This idempotency key was already used for a different transfer",
                )
            if previous["status"] == "pending":
                background_tasks.add_task(settle_transfer, previous["id"])
            return transaction_response(previous, sender_id)

        recipient = connection.execute(
            "SELECT id, email FROM users WHERE email = ?", (recipient_email,)
        ).fetchone()
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient account not found")
        if recipient["id"] == sender_id:
            raise HTTPException(status_code=422, detail="You cannot transfer to yourself")
        recipient_wallet = connection.execute(
            "SELECT id FROM wallets WHERE user_id = ? AND is_default = 1",
            (recipient["id"],),
        ).fetchone()
        if recipient_wallet is None:
            raise HTTPException(status_code=409, detail="Recipient has no active wallet")

        transaction_id = str(uuid.uuid4())
        created_at = now_iso()
        connection.execute(
            """INSERT INTO transactions
               (id, sender_id, recipient_id, amount_cents, status, idempotency_key,
                description, created_at, sender_wallet_id, recipient_wallet_id)
               VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)""",
            (
                transaction_id,
                sender_id,
                recipient["id"],
                amount_cents,
                request.idempotency_key,
                description,
                created_at,
                sender_wallet["id"],
                recipient_wallet["id"],
            ),
        )
        audit(
            connection,
            "transfer.pending",
            transaction_id,
            sender_id,
            {"recipient_id": recipient["id"], "amount_cents": amount_cents},
        )

        result = connection.execute(
            """SELECT t.*, s.email AS sender_email, r.email AS recipient_email,
                      sw.name AS sender_wallet_name, rw.name AS recipient_wallet_name
               FROM transactions t
               JOIN users s ON s.id = t.sender_id
               JOIN users r ON r.id = t.recipient_id
               LEFT JOIN wallets sw ON sw.id = t.sender_wallet_id
               LEFT JOIN wallets rw ON rw.id = t.recipient_wallet_id
               WHERE t.id = ?""",
            (transaction_id,),
        ).fetchone()
        response = transaction_response(result, sender_id)
    background_tasks.add_task(settle_transfer, transaction_id)
    return response


@app.get("/api/transactions")
def transactions(
    user: Annotated[dict[str, Any], Depends(current_user)],
    limit: int = 50,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 100")
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT t.*, s.email AS sender_email, r.email AS recipient_email,
                      sw.name AS sender_wallet_name, rw.name AS recipient_wallet_name
               FROM transactions t
               JOIN users s ON s.id = t.sender_id
               JOIN users r ON r.id = t.recipient_id
               LEFT JOIN wallets sw ON sw.id = t.sender_wallet_id
               LEFT JOIN wallets rw ON rw.id = t.recipient_wallet_id
               WHERE t.sender_id = ? OR t.recipient_id = ?
               ORDER BY t.created_at DESC LIMIT ?""",
            (user["id"], user["id"], limit),
        ).fetchall()
    return [transaction_response(row, user["id"]) for row in rows]


def invoice_response(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "issuer_email": row["issuer_email"],
        "customer_email": row["customer_email"],
        "wallet_name": row["wallet_name"],
        "amount": format_cents(row["amount_cents"]),
        "currency": row["currency"],
        "description": row["description"],
        "status": row["status"],
        "created_at": row["created_at"],
        "due_date": row["due_date"],
        "paid_transaction_id": row["paid_transaction_id"],
        "direction": row["direction"],
    }


@app.get("/api/invoices")
def invoices(user: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT invoices.*, issuer.email AS issuer_email,
                      customer.email AS customer_email, wallets.name AS wallet_name,
                      CASE WHEN invoices.issuer_id = ? THEN 'sent' ELSE 'received' END AS direction
               FROM invoices
               JOIN users issuer ON issuer.id = invoices.issuer_id
               JOIN users customer ON customer.id = invoices.customer_id
               JOIN wallets ON wallets.id = invoices.issuer_wallet_id
               WHERE invoices.issuer_id = ? OR invoices.customer_id = ?
               ORDER BY invoices.created_at DESC LIMIT 100""",
            (user["id"], user["id"], user["id"]),
        ).fetchall()
    return [invoice_response(row) for row in rows]


@app.post("/api/invoices", status_code=status.HTTP_201_CREATED)
def create_invoice(
    request: InvoiceRequest,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    customer_email = request.customer_email.strip().lower()
    amount_cents = int(request.amount * 100)
    if amount_cents <= 0:
        raise HTTPException(status_code=422, detail="Amount must be at least 0.01")
    if request.due_date:
        try:
            due_date = date.fromisoformat(request.due_date).isoformat()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Due date must use YYYY-MM-DD") from exc
    else:
        due_date = None
    invoice_id = str(uuid.uuid4())
    with connect_db() as connection:
        customer = connection.execute(
            "SELECT id FROM users WHERE email = ?", (customer_email,)
        ).fetchone()
        if customer is None:
            raise HTTPException(status_code=404, detail="Customer account not found")
        if customer["id"] == user["id"]:
            raise HTTPException(status_code=422, detail="You cannot invoice yourself")
        wallet_id = request.wallet_id or user["wallet_id"]
        issuer_wallet = connection.execute(
            "SELECT id, name FROM wallets WHERE id = ? AND user_id = ?",
            (wallet_id, user["id"]),
        ).fetchone()
        if issuer_wallet is None:
            raise HTTPException(status_code=404, detail="Invoice wallet not found")
        created_at = now_iso()
        connection.execute(
            """INSERT INTO invoices
               (id, issuer_id, issuer_wallet_id, customer_id, amount_cents, currency,
                description, status, created_at, due_date)
               VALUES (?, ?, ?, ?, ?, 'ZAR', ?, 'open', ?, ?)""",
            (
                invoice_id,
                user["id"],
                wallet_id,
                customer["id"],
                amount_cents,
                request.description.strip(),
                created_at,
                due_date,
            ),
        )
        audit(connection, "invoice.created", actor_id=user["id"], details={"invoice_id": invoice_id})
        row = connection.execute(
            """SELECT invoices.*, issuer.email AS issuer_email,
                      customer.email AS customer_email, wallets.name AS wallet_name,
                      'sent' AS direction
               FROM invoices
               JOIN users issuer ON issuer.id = invoices.issuer_id
               JOIN users customer ON customer.id = invoices.customer_id
               JOIN wallets ON wallets.id = invoices.issuer_wallet_id
               WHERE invoices.id = ?""",
            (invoice_id,),
        ).fetchone()
    return invoice_response(row)


@app.post("/api/invoices/{invoice_id}/pay")
def pay_invoice(
    invoice_id: str,
    request: InvoicePayRequest,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    with connect_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        invoice = connection.execute(
            """SELECT invoices.*, issuer.email AS issuer_email,
                      customer.email AS customer_email, issuer_wallet.name AS wallet_name,
                      'received' AS direction
               FROM invoices
               JOIN users issuer ON issuer.id = invoices.issuer_id
               JOIN users customer ON customer.id = invoices.customer_id
               JOIN wallets issuer_wallet ON issuer_wallet.id = invoices.issuer_wallet_id
               WHERE invoices.id = ?""",
            (invoice_id,),
        ).fetchone()
        if invoice is None or invoice["customer_id"] != user["id"]:
            raise HTTPException(status_code=404, detail="Invoice not found")
        previous = connection.execute(
            """SELECT transactions.*, payer.email AS sender_email,
                      issuer.email AS recipient_email, payer_wallet.name AS sender_wallet_name,
                      issuer_wallet.name AS recipient_wallet_name
               FROM transactions
               JOIN users payer ON payer.id = transactions.sender_id
               JOIN users issuer ON issuer.id = transactions.recipient_id
               LEFT JOIN wallets payer_wallet ON payer_wallet.id = transactions.sender_wallet_id
               LEFT JOIN wallets issuer_wallet ON issuer_wallet.id = transactions.recipient_wallet_id
               WHERE transactions.sender_id = ? AND transactions.idempotency_key = ?""",
            (user["id"], request.idempotency_key),
        ).fetchone()
        if previous:
            if previous["id"] == invoice["paid_transaction_id"]:
                return transaction_response(previous, user["id"])
            raise HTTPException(status_code=409, detail="This idempotency key was already used")
        if invoice["status"] != "open":
            raise HTTPException(status_code=409, detail="Invoice is no longer payable")
        wallet_id = request.wallet_id or user["wallet_id"]
        payer_wallet = connection.execute(
            "SELECT id, balance_cents FROM wallets WHERE id = ? AND user_id = ?",
            (wallet_id, user["id"]),
        ).fetchone()
        if payer_wallet is None:
            raise HTTPException(status_code=404, detail="Payment wallet not found")
        if payer_wallet["balance_cents"] < invoice["amount_cents"]:
            raise HTTPException(status_code=409, detail="Insufficient wallet balance")
        transaction_id = str(uuid.uuid4())
        created_at = now_iso()
        description = invoice["description"] or f"Invoice {invoice_id[:8]}"
        connection.execute(
            """INSERT INTO transactions
               (id, sender_id, recipient_id, amount_cents, currency, status,
                idempotency_key, description, created_at, sender_wallet_id, recipient_wallet_id)
               VALUES (?, ?, ?, ?, 'ZAR', 'successful', ?, ?, ?, ?, ?)""",
            (
                transaction_id,
                user["id"],
                invoice["issuer_id"],
                invoice["amount_cents"],
                request.idempotency_key,
                description,
                created_at,
                payer_wallet["id"],
                invoice["issuer_wallet_id"],
            ),
        )
        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents - ? WHERE id = ?",
            (invoice["amount_cents"], payer_wallet["id"]),
        )
        connection.execute(
            "UPDATE wallets SET balance_cents = balance_cents + ? WHERE id = ?",
            (invoice["amount_cents"], invoice["issuer_wallet_id"]),
        )
        connection.execute(
            "UPDATE invoices SET status = 'paid', paid_transaction_id = ? WHERE id = ?",
            (transaction_id, invoice_id),
        )
        audit(connection, "invoice.paid", transaction_id, user["id"], {"invoice_id": invoice_id})
        row = connection.execute(
            """SELECT transactions.*, payer.email AS sender_email,
                      issuer.email AS recipient_email, payer_wallet.name AS sender_wallet_name,
                      issuer_wallet.name AS recipient_wallet_name
               FROM transactions
               JOIN users payer ON payer.id = transactions.sender_id
               JOIN users issuer ON issuer.id = transactions.recipient_id
               JOIN wallets payer_wallet ON payer_wallet.id = transactions.sender_wallet_id
               JOIN wallets issuer_wallet ON issuer_wallet.id = transactions.recipient_wallet_id
               WHERE transactions.id = ?""",
            (transaction_id,),
        ).fetchone()
    return transaction_response(row, user["id"])


@app.post("/api/invoices/{invoice_id}/cancel")
def cancel_invoice(
    invoice_id: str,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, str]:
    with connect_db() as connection:
        result = connection.execute(
            """UPDATE invoices SET status = 'cancelled'
               WHERE id = ? AND issuer_id = ? AND status = 'open'""",
            (invoice_id, user["id"]),
        )
        if result.rowcount != 1:
            raise HTTPException(status_code=404, detail="Open invoice not found")
        audit(connection, "invoice.cancelled", actor_id=user["id"], details={"invoice_id": invoice_id})
    return {"id": invoice_id, "status": "cancelled"}


@app.get("/api/transactions/{transaction_id}/messages")
def transaction_messages(
    transaction_id: str,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> list[dict[str, Any]]:
    with connect_db() as connection:
        participant = connection.execute(
            """SELECT 1 FROM transactions
               WHERE id = ? AND (sender_id = ? OR recipient_id = ?)""",
            (transaction_id, user["id"], user["id"]),
        ).fetchone()
        if participant is None:
            raise HTTPException(status_code=404, detail="Transaction not found")
        rows = connection.execute(
            """SELECT messages.id, messages.sender_id, users.email AS sender_email,
                      messages.body, messages.created_at
               FROM transaction_messages messages
               JOIN users ON users.id = messages.sender_id
               WHERE messages.transaction_id = ?
               ORDER BY messages.created_at, messages.id""",
            (transaction_id,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/transactions/{transaction_id}/messages", status_code=status.HTTP_201_CREATED)
def create_transaction_message(
    transaction_id: str,
    request: MessageRequest,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    body = request.body.strip()
    if not body:
        raise HTTPException(status_code=422, detail="Message cannot be empty")
    with connect_db() as connection:
        participant = connection.execute(
            """SELECT 1 FROM transactions
               WHERE id = ? AND (sender_id = ? OR recipient_id = ?)""",
            (transaction_id, user["id"], user["id"]),
        ).fetchone()
        if participant is None:
            raise HTTPException(status_code=404, detail="Transaction not found")
        message_id = str(uuid.uuid4())
        created_at = now_iso()
        connection.execute(
            """INSERT INTO transaction_messages (id, transaction_id, sender_id, body, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (message_id, transaction_id, user["id"], body, created_at),
        )
    return {
        "id": message_id,
        "transaction_id": transaction_id,
        "sender_id": user["id"],
        "sender_email": user["email"],
        "body": body,
        "created_at": created_at,
    }


@app.get("/api/analytics")
def analytics(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    with connect_db() as connection:
        totals = connection.execute(
            """SELECT
                   COALESCE(SUM(CASE WHEN sender_id = ? THEN amount_cents ELSE 0 END), 0) AS sent_cents,
                   COALESCE(SUM(CASE WHEN recipient_id = ? THEN amount_cents ELSE 0 END), 0) AS received_cents,
                   COUNT(*) AS transaction_count
               FROM transactions
               WHERE status = 'successful' AND (sender_id = ? OR recipient_id = ?)""",
            (user["id"], user["id"], user["id"], user["id"]),
        ).fetchone()
        monthly = connection.execute(
            """SELECT month, SUM(sent_cents) AS sent_cents,
                      SUM(received_cents) AS received_cents
               FROM (
                   SELECT substr(created_at, 1, 7) AS month,
                          CASE WHEN sender_id = ? THEN amount_cents ELSE 0 END AS sent_cents,
                          CASE WHEN recipient_id = ? THEN amount_cents ELSE 0 END AS received_cents
                   FROM transactions
                   WHERE status = 'successful' AND (sender_id = ? OR recipient_id = ?)
                     AND substr(created_at, 1, 7) >= strftime('%Y-%m', 'now', '-5 months')
                   UNION ALL
                   SELECT substr(created_at, 1, 7), 0, amount_cents
                   FROM stripe_topups
                   WHERE user_id = ? AND status = 'paid'
                     AND substr(created_at, 1, 7) >= strftime('%Y-%m', 'now', '-5 months')
               )
               GROUP BY month ORDER BY month""",
            (user["id"], user["id"], user["id"], user["id"], user["id"]),
        ).fetchall()
        topup_total = connection.execute(
            """SELECT COALESCE(SUM(amount_cents), 0) FROM stripe_topups
               WHERE user_id = ? AND status = 'paid'""",
            (user["id"],),
        ).fetchone()[0]
    return {
        "currency": user["currency"],
        "sent": format_cents(totals["sent_cents"]),
        "received": format_cents(totals["received_cents"] + topup_total),
        "transaction_count": totals["transaction_count"],
        "monthly": [
            {
                "month": row["month"],
                "sent": format_cents(row["sent_cents"]),
                "received": format_cents(row["received_cents"]),
            }
            for row in monthly
        ],
    }


@app.get("/api/transactions/{transaction_id}/receipt")
def receipt(
    transaction_id: str,
    user: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute(
            """SELECT t.*, s.email AS sender_email, r.email AS recipient_email,
                      sw.name AS sender_wallet_name, rw.name AS recipient_wallet_name
               FROM transactions t
               JOIN users s ON s.id = t.sender_id
               JOIN users r ON r.id = t.recipient_id
               LEFT JOIN wallets sw ON sw.id = t.sender_wallet_id
               LEFT JOIN wallets rw ON rw.id = t.recipient_wallet_id
               WHERE t.id = ? AND (t.sender_id = ? OR t.recipient_id = ?)""",
            (transaction_id, user["id"], user["id"]),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Receipt not found")
    return {
        "receipt_id": f"R-{row['id']}",
        "issued_at": now_iso(),
        "transaction": transaction_response(row, user["id"]),
        "notice": "Simulated payment receipt; no real funds were moved.",
    }


@app.get("/api/admin/audit")
def audit_log(
    _: Annotated[dict[str, Any], Depends(require_admin)],
    limit: int = 100,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 500")
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT audit_logs.id, audit_logs.transaction_id, audit_logs.actor_id,
                      users.email AS actor_email, audit_logs.action, audit_logs.details,
                      audit_logs.created_at
               FROM audit_logs LEFT JOIN users ON users.id = audit_logs.actor_id
               ORDER BY audit_logs.created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "transaction_id": row["transaction_id"],
            "actor_id": row["actor_id"],
            "actor_email": row["actor_email"],
            "action": row["action"],
            "details": json.loads(row["details"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
if __name__ == "__main__":
    app.run(debug=True)