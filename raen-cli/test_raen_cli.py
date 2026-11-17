#!/usr/bin/env python3
"""Unit tests for raen-cli: EIP-3009 / EIP-712 signing, challenge decoding, and dry-run safety."""

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path
import unittest

from eth_account import Account
from eth_account.messages import encode_typed_data

# Dynamically import raen-cli.py (with hyphen in filename)
CLI_PATH = Path(__file__).parent / "raen-cli.py"
spec = importlib.util.spec_from_file_location("raen_cli", CLI_PATH)
cli = importlib.util.module_from_spec(spec)
sys.modules["raen_cli"] = cli
spec.loader.exec_module(cli)


class TestRaenCli(unittest.TestCase):
    def setUp(self):
        # Deterministic, unfunded test private key
        self.test_privkey = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
        self.account = Account.from_key(self.test_privkey)
        self.payer_addr = self.account.address

    def test_keccak_hash_standard(self):
        """Verify keccak256 matches Ethereum specification (not NIST sha3_256)."""
        empty_hash = cli.keccak256(b"")
        self.assertEqual(
            empty_hash.hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_sign_auth_recovers_exact_signer(self):
        """Verify EIP-3009 signature can be verified/recovered by eth-account."""
        to_addr = "0x9b8a27e03ceba490953cda8ab1291c0e13baf72f"
        value = 50000  # $0.05 USDC (6 decimals)
        valid_after = 0
        valid_before = 1893456000
        nonce = os.urandom(32)

        sig_hex, payer, full_msg = cli.sign_authorization(
            privkey=self.test_privkey,
            to_addr=to_addr,
            value=value,
            valid_after=valid_after,
            valid_before=valid_before,
            nonce=nonce,
            asset=cli.USDC_BASE,
            chain_id=cli.BASE_CHAIN_ID,
            token_name="USD Coin",
            token_version="2",
        )

        self.assertEqual(payer.lower(), self.payer_addr.lower())

        # Recover signer from the typed data message and signature
        signable_msg = encode_typed_data(full_message=full_msg)
        recovered = Account.recover_message(signable_msg, signature=sig_hex)
        self.assertEqual(recovered.lower(), self.payer_addr.lower())

    def test_nonce_and_fields_match_between_signature_and_payload(self):
        """Ensure nonce, timestamps, and amounts in authorization match the signed data."""
        client = cli.X402Client(private_key=self.test_privkey)
        challenge = {
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "asset": cli.USDC_BASE,
                    "amount": "50000",
                    "payTo": "0x9b8a27e03ceba490953cda8ab1291c0e13baf72f",
                    "maxTimeoutSeconds": 120,
                    "extra": {"name": "USD Coin", "version": "2"},
                }
            ],
        }

        header_name, header_val, payer, amount = client.prepare_payment(challenge)
        self.assertEqual(header_name, "PAYMENT-SIGNATURE")
        self.assertEqual(payer.lower(), self.payer_addr.lower())
        self.assertEqual(amount, "50000")

        # Decode payload
        decoded_json = json.loads(base64.b64decode(header_val).decode())
        auth = decoded_json["payload"]["authorization"]
        sig = decoded_json["payload"]["signature"]

        # Validate that the recovered address matches with the authorization values in the payload
        full_msg = cli.build_typed_data(
            from_addr=auth["from"],
            to_addr=auth["to"],
            value=int(auth["value"]),
            valid_after=int(auth["validAfter"]),
            valid_before=int(auth["validBefore"]),
            nonce=bytes.fromhex(auth["nonce"].replace("0x", "")),
            asset=cli.USDC_BASE,
            chain_id=cli.BASE_CHAIN_ID,
            token_name="USD Coin",
            token_version="2",
        )

        signable_msg = encode_typed_data(full_message=full_msg)
        recovered = Account.recover_message(signable_msg, signature=sig)
        self.assertEqual(recovered.lower(), self.payer_addr.lower())

    def test_v1_challenge_preparation(self):
        """Verify x402 v1 challenge produces X-PAYMENT envelope."""
        client = cli.X402Client(private_key=self.test_privkey)
        challenge_v1 = {
            "x402Version": 1,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "maxAmountRequired": "50000",
                    "payTo": "0x9b8a27e03ceba490953cda8ab1291c0e13baf72f",
                }
            ],
        }

        header_name, header_val, payer, amount = client.prepare_payment(challenge_v1)
        self.assertEqual(header_name, "X-PAYMENT")
        self.assertEqual(amount, "50000")
        decoded_json = json.loads(base64.b64decode(header_val).decode())
        self.assertEqual(decoded_json.get("x402Version"), 1)
        self.assertIn("signature", decoded_json["payload"])

    def test_max_spending_cap_enforcement(self):
        """Client should raise RuntimeError when amount exceeds max_amount cap."""
        client = cli.X402Client(private_key=self.test_privkey, max_amount=10000)
        challenge = {
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "50000",
                    "payTo": "0x9b8a27e03ceba490953cda8ab1291c0e13baf72f",
                }
            ],
        }
        with self.assertRaises(RuntimeError) as ctx:
            client.prepare_payment(challenge)
        self.assertIn("exceeds configured max spending cap", str(ctx.exception))

    def test_decode_v1_and_v2_headers_case_insensitive(self):
        """Test challenge decoding with case-insensitive HTTP header keys."""
        client = cli.X402Client()
        challenge_v1 = {
            "x402Version": 1,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "maxAmountRequired": "10000",
                    "payTo": "0x9b8a27e03ceba490953cda8ab1291c0e13baf72f",
                }
            ],
        }
        b64_val = base64.b64encode(json.dumps(challenge_v1).encode()).decode()

        # lowercase
        decoded = client._decode_payment_required({"payment-required": b64_val})
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.get("x402Version"), 1)

        # uppercase
        decoded = client._decode_payment_required({"PAYMENT-REQUIRED": b64_val})
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.get("x402Version"), 1)

    def test_dry_run_does_not_fire_network_request(self):
        """Dry-run mode should not attempt live signing or real payment transmission."""
        client = cli.X402Client(dry_run=True)
        challenge = {
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "asset": cli.USDC_BASE,
                    "amount": "50000",
                    "payTo": "0x9b8a27e03ceba490953cda8ab1291c0e13baf72f",
                }
            ],
        }
        hdr_name, hdr_val, payer, amount = client.prepare_payment(challenge)
        self.assertTrue(payer.startswith("0x[dry-run]"))
        self.assertIn("MOCK_DRY_RUN", hdr_val)


if __name__ == "__main__":
    unittest.main()
