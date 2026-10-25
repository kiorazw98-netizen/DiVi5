import hashlib
import hmac
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

import app as wallet


class WalletApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_db_path = wallet.DB_PATH
        wallet.DB_PATH = Path(self.temp_dir.name) / "test-wallet.db"
        self.client = TestClient(wallet.app)
        self.client.__enter__()
        self.alice = self.login("alice@example.com", "alice-demo-password")
        self.bob = self.login("bob@example.com", "bob-demo-password")

    def tearDown(self):
        self.client.__exit__(None, None, None)
        wallet.DB_PATH = self.previous_db_path
        self.temp_dir.cleanup()

    def login(self, email, password):
        response = self.client.post(
            "/api/login", json={"email": email, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["token"]

    def headers(self, token):
        return {"Authorization": f"Bearer {token}"}

    def transfer(self, token, key, amount="10.00", recipient="bob@example.com"):
        return self.client.post(
            "/api/transfers",
            headers=self.headers(token),
            json={
                "recipient_email": recipient,
                "amount": amount,
                "idempotency_key": key,
                "description": "Lunch",
            },
        )

    def test_transfer_is_atomic_idempotent_and_receipted(self):
        response = self.transfer(self.alice, "unique-key-0001")
        self.assertEqual(response.status_code, 201)
        transaction = response.json()
        self.assertEqual(transaction["status"], "pending")
        self.assertEqual(transaction["amount"], "10.00")
        self.assertEqual(transaction["currency"], "ZAR")
        self.assertEqual(
            self.client.get("/api/me", headers=self.headers(self.alice)).json()["currency"],
            "ZAR",
        )

        duplicate = self.transfer(self.alice, "unique-key-0001")
        self.assertEqual(duplicate.status_code, 201)
        self.assertEqual(duplicate.json()["id"], transaction["id"])
        self.assertEqual(duplicate.json()["status"], "successful")
        self.assertEqual(
            self.client.get("/api/me", headers=self.headers(self.alice)).json()["balance"],
            "990.00",
        )
        self.assertEqual(
            self.client.get("/api/me", headers=self.headers(self.bob)).json()["balance"],
            "260.00",
        )
        history = self.client.get(
            "/api/transactions", headers=self.headers(self.bob)
        ).json()
        self.assertEqual(history[0]["direction"], "received")
        self.assertEqual(history[0]["status"], "successful")

        receipt = self.client.get(
            f"/api/transactions/{transaction['id']}/receipt",
            headers=self.headers(self.bob),
        )
        self.assertEqual(receipt.status_code, 200)
        self.assertEqual(receipt.json()["transaction"]["id"], transaction["id"])
        self.assertIn("no real funds", receipt.json()["notice"])

        admin = self.login("admin@example.com", "admin-demo-password")
        audit = self.client.get("/api/admin/audit", headers=self.headers(admin))
        self.assertEqual(audit.status_code, 200)
        self.assertEqual(
            [entry["action"] for entry in audit.json()[:2]],
            ["transfer.successful", "transfer.pending"],
        )

    def test_idempotency_key_cannot_be_reused_for_a_different_payment(self):
        self.transfer(self.alice, "unique-key-0002")
        response = self.transfer(
            self.alice, "unique-key-0002", amount="11.00"
        )
        self.assertEqual(response.status_code, 409)

    def test_insufficient_balance_creates_failed_payment_without_debit(self):
        response = self.transfer(
            self.bob, "unique-key-0003", amount="500.00", recipient="alice@example.com"
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "pending")
        failed = self.client.get(
            "/api/transactions", headers=self.headers(self.bob)
        ).json()[0]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["failure_reason"], "Insufficient balance")
        balance = self.client.get("/api/me", headers=self.headers(self.bob)).json()["balance"]
        self.assertEqual(balance, "250.00")

    def test_login_and_permissions_are_enforced(self):
        wrong_password = self.client.post(
            "/api/login",
            json={"email": "alice@example.com", "password": "not-the-password"},
        )
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(
            self.client.get("/api/me").status_code,
            401,
        )
        self.assertEqual(
            self.client.get("/api/admin/audit", headers=self.headers(self.alice)).status_code,
            403,
        )

    def test_register_creates_a_zero_balance_user(self):
        response = self.client.post(
            "/api/register",
            json={"email": "new@example.com", "password": "new-account-password"},
        )
        self.assertEqual(response.status_code, 201)
        token = response.json()["token"]
        account = self.client.get("/api/me", headers=self.headers(token))
        self.assertEqual(account.status_code, 200)
        self.assertEqual(account.json()["balance"], "0.00")
        duplicate = self.client.post(
            "/api/register",
            json={"email": "new@example.com", "password": "new-account-password"},
        )
        self.assertEqual(duplicate.status_code, 409)

    def test_receipt_is_private_to_transfer_participants(self):
        transaction = self.transfer(self.alice, "unique-key-0004").json()
        self.client.post(
            "/api/register",
            json={"email": "third@example.com", "password": "third-account-password"},
        )
        third_token = self.login("third@example.com", "third-account-password")
        response = self.client.get(
            f"/api/transactions/{transaction['id']}/receipt",
            headers=self.headers(third_token),
        )
        self.assertEqual(response.status_code, 404)
        messages = self.client.get(
            f"/api/transactions/{transaction['id']}/messages",
            headers=self.headers(third_token),
        )
        self.assertEqual(messages.status_code, 404)

    def test_wallets_invoices_messages_and_analytics(self):
        savings = self.client.post(
            "/api/wallets",
            headers=self.headers(self.alice),
            json={"name": "Savings"},
        )
        self.assertEqual(savings.status_code, 201)
        savings_id = savings.json()["id"]

        invoice = self.client.post(
            "/api/invoices",
            headers=self.headers(self.alice),
            json={
                "customer_email": "bob@example.com",
                "amount": "30.00",
                "description": "Design work",
                "wallet_id": savings_id,
            },
        )
        self.assertEqual(invoice.status_code, 201)
        self.assertEqual(invoice.json()["status"], "open")
        invoice_id = invoice.json()["id"]
        payment = self.client.post(
            f"/api/invoices/{invoice_id}/pay",
            headers=self.headers(self.bob),
            json={"idempotency_key": "invoice-payment-01"},
        )
        self.assertEqual(payment.status_code, 200)
        self.assertEqual(payment.json()["status"], "successful")
        duplicate_payment = self.client.post(
            f"/api/invoices/{invoice_id}/pay",
            headers=self.headers(self.bob),
            json={"idempotency_key": "invoice-payment-01"},
        )
        self.assertEqual(duplicate_payment.status_code, 200)
        self.assertEqual(duplicate_payment.json()["id"], payment.json()["id"])

        transfer = self.client.post(
            "/api/transfers",
            headers=self.headers(self.alice),
            json={
                "recipient_email": "bob@example.com",
                "amount": "12.00",
                "idempotency_key": "savings-transfer-01",
                "wallet_id": savings_id,
            },
        )
        self.assertEqual(transfer.status_code, 201)
        transaction_id = transfer.json()["id"]
        self.assertEqual(transfer.json()["sender_wallet_name"], "Savings")
        savings_balance = next(
            wallet["balance"]
            for wallet in self.client.get(
                "/api/wallets", headers=self.headers(self.alice)
            ).json()
            if wallet["id"] == savings_id
        )
        self.assertEqual(savings_balance, "18.00")

        message = self.client.post(
            f"/api/transactions/{transaction_id}/messages",
            headers=self.headers(self.alice),
            json={"body": "Payment sent from savings"},
        )
        self.assertEqual(message.status_code, 201)
        recipient_messages = self.client.get(
            f"/api/transactions/{transaction_id}/messages",
            headers=self.headers(self.bob),
        )
        self.assertEqual(recipient_messages.status_code, 200)
        self.assertEqual(recipient_messages.json()[0]["body"], "Payment sent from savings")
        alice_invoices = self.client.get(
            "/api/invoices", headers=self.headers(self.alice)
        ).json()
        self.assertEqual(alice_invoices[0]["status"], "paid")

        analytics = self.client.get(
            "/api/analytics", headers=self.headers(self.alice)
        )
        self.assertEqual(analytics.status_code, 200)
        self.assertEqual(analytics.json()["sent"], "12.00")
        self.assertEqual(analytics.json()["received"], "30.00")
        self.assertEqual(analytics.json()["transaction_count"], 2)

    def test_stripe_webhook_credits_topup_once_after_signed_payment(self):
        secret = "whsec_test_fixture"
        with wallet.connect_db() as connection:
            wallet_row = connection.execute(
                "SELECT id FROM wallets WHERE user_id = 1 AND is_default = 1"
            ).fetchone()
            connection.execute(
                """INSERT INTO stripe_topups
                   (id, user_id, wallet_id, amount_cents, currency, status,
                    stripe_session_id, created_at)
                   VALUES (?, 1, ?, 500, 'ZAR', 'pending', 'cs_test_fixture', ?)""",
                ("topup-test-fixture", wallet_row["id"], wallet.now_iso()),
            )
        payload = json.dumps(
            {
                "type": "checkout.session.completed",
                "data": {
                    "object": {
                        "id": "cs_test_fixture",
                        "mode": "payment",
                        "currency": "zar",
                        "amount_total": 500,
                        "payment_status": "paid",
                        "metadata": {"topup_id": "topup-test-fixture"},
                    }
                },
            },
            separators=(",", ":"),
        ).encode()
        timestamp = int(time.time())
        signature = hmac.new(
            secret.encode(),
            str(timestamp).encode() + b"." + payload,
            hashlib.sha256,
        ).hexdigest()
        with patch.dict("os.environ", {"STRIPE_WEBHOOK_SECRET": secret}):
            invalid_signature = self.client.post(
                "/api/stripe/webhook",
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": f"t={timestamp},v1=invalid",
                },
            )
            response = self.client.post(
                "/api/stripe/webhook",
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": f"t={timestamp},v1={signature}",
                },
            )
            duplicate = self.client.post(
                "/api/stripe/webhook",
                content=payload,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": f"t={timestamp},v1={signature}",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(invalid_signature.status_code, 400)
        self.assertEqual(duplicate.status_code, 200)
        balance = self.client.get(
            "/api/me", headers=self.headers(self.alice)
        ).json()["balance"]
        self.assertEqual(balance, "1005.00")
        topups = self.client.get("/api/topups", headers=self.headers(self.alice)).json()
        self.assertEqual(topups[0]["status"], "paid")
        analytics = self.client.get(
            "/api/analytics", headers=self.headers(self.alice)
        ).json()
        self.assertEqual(analytics["received"], "5.00")
        self.assertEqual(analytics["transaction_count"], 0)

    def test_stripe_checkout_requires_server_side_configuration(self):
        with patch.dict("os.environ", {}, clear=True):
            response = self.client.post(
                "/api/topups/checkout",
                headers=self.headers(self.alice),
                json={"amount": "10.00", "wallet_id": 1},
            )
        self.assertEqual(response.status_code, 503)

    def test_stripe_checkout_creates_pending_topup_and_returns_checkout_url(self):
        stripe_response = MagicMock()
        stripe_response.__enter__.return_value.read.return_value = (
            b'{"id":"cs_test_checkout","url":"https://checkout.stripe.test/session"}'
        )
        with (
            patch.dict(
                "os.environ",
                {
                    "STRIPE_SECRET_KEY": "sk_test_configured",
                    "STRIPE_WEBHOOK_SECRET": "whsec_configured",
                },
            ),
            patch.object(wallet, "urlopen", return_value=stripe_response),
        ):
            response = self.client.post(
                "/api/topups/checkout",
                headers=self.headers(self.alice),
                json={"amount": "25.00", "wallet_id": 1},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["checkout_url"],
            "https://checkout.stripe.test/session",
        )
        with wallet.connect_db() as connection:
            topup = connection.execute(
                "SELECT amount_cents, status, stripe_session_id FROM stripe_topups"
            ).fetchone()
        self.assertEqual(topup["amount_cents"], 2500)
        self.assertEqual(topup["status"], "pending")
        self.assertEqual(topup["stripe_session_id"], "cs_test_checkout")

    def test_legacy_single_wallet_database_migrates_balances(self):
        legacy_path = Path(self.temp_dir.name) / "legacy-wallet.db"
        connection = sqlite3.connect(legacy_path)
        connection.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE wallets (
                user_id INTEGER PRIMARY KEY REFERENCES users(id),
                balance_cents INTEGER NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'USD'
            );
            CREATE TABLE transactions (
                id TEXT PRIMARY KEY,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL,
                currency TEXT NOT NULL DEFAULT 'USD',
                status TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                failure_reason TEXT,
                created_at TEXT NOT NULL,
                UNIQUE (sender_id, idempotency_key)
            );
            INSERT INTO users VALUES (1, 'legacy@example.com', 'unused', 'user', '2025-01-01');
            INSERT INTO wallets VALUES (1, 12345, 'USD');
            """
        )
        connection.commit()
        connection.close()

        original_db_path = wallet.DB_PATH
        try:
            wallet.DB_PATH = legacy_path
            wallet.initialize_db()
            with wallet.connect_db() as migrated:
                wallets = migrated.execute(
                    "SELECT name, balance_cents, currency, is_default FROM wallets"
                ).fetchall()
                foreign_key_errors = migrated.execute("PRAGMA foreign_key_check").fetchall()
            self.assertEqual(len(wallets), 1)
            self.assertEqual(wallets[0]["name"], "Main wallet")
            self.assertEqual(wallets[0]["balance_cents"], 12345)
            self.assertEqual(wallets[0]["currency"], "ZAR")
            self.assertEqual(wallets[0]["is_default"], 1)
            self.assertEqual(foreign_key_errors, [])
        finally:
            wallet.DB_PATH = original_db_path


if __name__ == "__main__":
    unittest.main()
