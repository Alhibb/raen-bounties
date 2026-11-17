#!/usr/bin/env python3
"""raen-cli.py — Robust one-file Python CLI for the RAEN 12-service x402 fleet.

Supports EIP-3009 TransferWithAuthorization micropayments over x402 v1 and v2.
Uses eth-account for standards-compliant EIP-712 typed signing.
"""

import argparse
import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from eth_account import Account
from eth_utils import keccak

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------
RAEN_GATEWAY = "https://raen-mcp-gateway.fly.dev"
DIRECTORY_URL = "https://bshelby88.github.io/raen-agent-directory/agents.json"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_CHAIN_ID = 8453


# ---------------------------------------------------------------------------
# Cryptographic Helpers (EIP-712 / EIP-3009)
# ---------------------------------------------------------------------------
def keccak256(data: bytes) -> bytes:
    """Return standard Ethereum Keccak-256 digest."""
    return keccak(data)


def build_typed_data(
    from_addr: str,
    to_addr: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
    asset: str = USDC_BASE,
    chain_id: int = BASE_CHAIN_ID,
    token_name: str = "USD Coin",
    token_version: str = "2",
) -> Dict[str, Any]:
    """Construct standard EIP-712 typed data dictionary for EIP-3009 TransferWithAuthorization."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": asset,
        },
        "message": {
            "from": from_addr,
            "to": to_addr,
            "value": value,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": "0x" + nonce.hex() if isinstance(nonce, bytes) else nonce,
        },
    }


def sign_authorization(
    privkey: str,
    to_addr: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
    asset: str = USDC_BASE,
    chain_id: int = BASE_CHAIN_ID,
    token_name: str = "USD Coin",
    token_version: str = "2",
) -> Tuple[str, str, Dict[str, Any]]:
    """Sign EIP-3009 TransferWithAuthorization using eth-account."""
    pk = "0x" + privkey if not privkey.startswith("0x") else privkey
    acct = Account.from_key(pk)
    typed_data = build_typed_data(
        from_addr=acct.address,
        to_addr=to_addr,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
        asset=asset,
        chain_id=chain_id,
        token_name=token_name,
        token_version=token_version,
    )
    signed = Account.sign_typed_data(pk, full_message=typed_data)
    sig_hex = "0x" + bytes(signed.signature).hex()
    return sig_hex, acct.address, typed_data


# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------
class X402Client:
    def __init__(
        self,
        gateway_url: str = RAEN_GATEWAY,
        api_key: Optional[str] = None,
        private_key: Optional[str] = None,
        dry_run: bool = False,
        max_amount: Optional[int] = None,
    ):
        self.gateway = gateway_url.rstrip("/")
        self.api_key = api_key or os.environ.get("RAEN_API_KEY", "")
        self.private_key = private_key or os.environ.get("RAEN_PRIVATE_KEY", "")
        self.dry_run = dry_run
        self.max_amount = max_amount
        self.payer_address: Optional[str] = None

    def _req(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: int = 20,
    ) -> Tuple[int, Dict[str, str], bytes]:
        req_headers = {
            "User-Agent": "raen-cli/2.0",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)
        if self.api_key:
            req_headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def list_services(self) -> List[Dict[str, Any]]:
        """Fetch fleet services catalog."""
        # Check agents.json directory first
        status, _, body = self._req(DIRECTORY_URL)
        if status == 200:
            try:
                data = json.loads(body.decode("utf-8"))
                if "services" in data:
                    return data["services"]
            except Exception:
                pass

        # Fallback to gateway /.well-known/agent.json
        url = f"{self.gateway}/.well-known/agent.json"
        status, _, body = self._req(url)
        if status != 200:
            raise RuntimeError(f"Failed to fetch fleet directory: HTTP {status}")
        data = json.loads(body.decode("utf-8"))
        return data.get("skills", data.get("services", []))

    def _get_header(self, headers: Dict[str, str], target: str) -> Optional[str]:
        target_lower = target.lower()
        for k, v in headers.items():
            if k.lower() == target_lower:
                return v
        return None

    def _decode_payment_required(self, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        val = self._get_header(headers, "payment-required")
        if not val:
            return None
        try:
            return json.loads(base64.b64decode(val, validate=True).decode("utf-8"))
        except Exception as e:
            print(f"  [warn] Failed decoding payment-required header: {e}")
            return None

    def _decode_payment_response(self, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        val = self._get_header(headers, "payment-response") or self._get_header(
            headers, "x-payment-response"
        )
        if not val:
            return None
        try:
            return json.loads(base64.b64decode(val, validate=True).decode("utf-8"))
        except Exception:
            return None

    def _select_option(self, payment_req: Dict[str, Any]) -> Dict[str, Any]:
        accepts = payment_req.get("accepts", [])
        if not accepts:
            raise RuntimeError("402 challenge contained no accepts[] requirements")

        # Prefer exact scheme on Base (eip155:8453 or base)
        for opt in accepts:
            net = opt.get("network", "")
            scheme = opt.get("scheme", "")
            if scheme == "exact" and net in ("eip155:8453", "base"):
                return opt
        return accepts[0]

    def prepare_payment(self, payment_req: Dict[str, Any]) -> Tuple[str, str, str, str]:
        """Build payment authorization envelope and signature.

        Returns: (header_name, base64_payload, payer_address, amount_atomic)
        """
        accepted = self._select_option(payment_req)
        version = payment_req.get("x402Version", 2)
        amount_str = str(accepted.get("amount") or accepted.get("maxAmountRequired") or "0")
        amount = int(amount_str)

        if self.max_amount is not None and amount > self.max_amount:
            raise RuntimeError(
                f"Required amount {amount} exceeds configured max spending cap {self.max_amount}"
            )

        pay_to = accepted.get("payTo", "")
        timeout_sec = min(int(accepted.get("maxTimeoutSeconds", 120)), 600)
        now = int(time.time())
        valid_after = 0 if version == 2 else max(0, now - 600)
        valid_before = now + timeout_sec
        nonce = secrets.token_bytes(32)

        extra = accepted.get("extra") or {}
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except Exception:
                extra = {}
        token_name = extra.get("name", "USD Coin")
        token_version = extra.get("version", "2")
        asset = accepted.get("asset", USDC_BASE)

        if self.dry_run or not self.private_key:
            mock_addr = "0x[dry-run]" + secrets.token_hex(16)
            mock_payload = {
                "dryRun": True,
                "amount": amount_str,
                "payTo": pay_to,
                "token": token_name,
            }
            return (
                "PAYMENT-SIGNATURE" if version == 2 else "X-PAYMENT",
                "MOCK_DRY_RUN_" + base64.b64encode(json.dumps(mock_payload).encode()).decode(),
                mock_addr,
                amount_str,
            )

        sig_hex, payer, _ = sign_authorization(
            privkey=self.private_key,
            to_addr=pay_to,
            value=amount,
            valid_after=valid_after,
            valid_before=valid_before,
            nonce=nonce,
            asset=asset,
            chain_id=BASE_CHAIN_ID,
            token_name=token_name,
            token_version=token_version,
        )

        auth_msg = {
            "from": payer,
            "to": pay_to,
            "value": str(amount),
            "validAfter": str(valid_after),
            "validBefore": str(valid_before),
            "nonce": "0x" + nonce.hex(),
        }

        if version == 1:
            header_name = "X-PAYMENT"
            envelope = {
                "x402Version": 1,
                "scheme": accepted.get("scheme", "exact"),
                "network": accepted.get("network", "eip155:8453"),
                "payload": {"signature": sig_hex, "authorization": auth_msg},
            }
        else:
            header_name = "PAYMENT-SIGNATURE"
            envelope = {
                "x402Version": 2,
                "accepted": accepted,
                "payload": {"signature": sig_hex, "authorization": auth_msg},
            }
            if "resource" in payment_req:
                envelope["resource"] = payment_req["resource"]

        b64_payload = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode()).decode()
        return header_name, b64_payload, payer, amount_str

    def call_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool call via the RAEN MCP gateway with x402 payment handling."""
        url = f"{self.gateway}/mcp"
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
            "id": 1,
        }).encode("utf-8")

        status, hdrs, body = self._req(url, method="POST", headers={"Content-Type": "application/json"}, body=payload)

        if status == 402:
            payment_req = self._decode_payment_required(hdrs)
            if not payment_req:
                raise RuntimeError("HTTP 402 received without a valid PAYMENT-REQUIRED header")

            print("\n[x402] Payment Required:")
            header_name, header_val, payer, amount = self.prepare_payment(payment_req)
            self.payer_address = payer

            accepted = self._select_option(payment_req)
            print(f"  Amount:   {amount} atomic units ({accepted.get('asset', USDC_BASE)[:16]}...)")
            print(f"  Pay-to:   {accepted.get('payTo', '')}")
            print(f"  Payer:    {payer}")

            if self.dry_run:
                print("\n  [dry-run] Payment challenge inspected successfully. Simulated call aborted.")
                return {
                    "dry_run": True,
                    "status": "payment_challenge_verified",
                    "payer": payer,
                    "amount": amount,
                    "payTo": accepted.get("payTo", ""),
                }

            # Resend with payment header
            status2, hdrs2, body2 = self._req(
                url,
                method="POST",
                headers={"Content-Type": "application/json", header_name: header_val},
                body=payload,
            )

            receipt = self._decode_payment_response(hdrs2)
            if receipt:
                print("\n[x402 Settlement Receipt]:")
                print(f"  Success:     {receipt.get('success')}")
                if "transaction" in receipt:
                    print(f"  Transaction: {receipt.get('transaction')}")
                print(f"  Network:     {receipt.get('network')}")
                print(f"  Payer:       {receipt.get('payer', payer)}")

            if 200 <= status2 < 300:
                try:
                    return json.loads(body2.decode("utf-8"))
                except Exception:
                    return {"result": body2.decode("utf-8", errors="replace")}
            else:
                err_text = body2.decode("utf-8", errors="replace")
                raise RuntimeError(f"HTTP {status2} after payment submission: {err_text[:300]}")

        elif 200 <= status < 300:
            return json.loads(body.decode("utf-8"))
        else:
            err_text = body.decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {status}: {err_text[:300]}")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
SERVICES = [
    "raen_law_lookup",
    "raen_ticker_analysis",
    "raen_dispute_letter",
    "raen_image_generate",
    "raen_contract_analysis",
]


def main():
    ap = argparse.ArgumentParser(
        prog="raen-cli",
        description="RAEN x402 CLI — micropayments client for the 12-service RAEN fleet on Base.",
    )
    ap.add_argument("service", nargs="?", help="Service or MCP tool name (e.g. raen_law_lookup)")
    ap.add_argument("prompt", nargs="?", help="Prompt or task argument")
    ap.add_argument("--list", action="store_true", help="List all fleet services from agents.json")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate and inspect 402 challenge without signing or sending payment",
    )
    ap.add_argument("--key", dest="api_key", help="RAEN gateway Bearer dev key (optional)")
    ap.add_argument(
        "--max-amount",
        type=int,
        dest="max_amount",
        help="Max atomic units of USDC approved to spend (spending cap safety guard)",
    )
    ap.add_argument("--json", action="store_true", dest="pretty", help="Pretty-print JSON output")
    args = ap.parse_args()

    privkey = os.environ.get("RAEN_PRIVATE_KEY", "")
    dry = args.dry_run or not privkey

    if args.list or (not args.service and not args.prompt):
        client = X402Client(api_key=args.api_key)
        try:
            services = client.list_services()
            print(f"\n{'=' * 64}")
            print(f"  RAEN Fleet Services ({len(services)} services on Base Mainnet)")
            print(f"{'=' * 64}\n")
            for s in services:
                name = s.get("name") or s.get("id") or "?"
                endpoint = s.get("endpoint") or s.get("description", "")
                print(f"  {name:<28} {endpoint}")
            print("\nUsage:")
            print("  python raen-cli.py <service> '<prompt>' [--dry-run]")
            print("\nExamples:")
            for ex in SERVICES[:3]:
                print(f"  python raen-cli.py {ex} 'test prompt' --dry-run")
            print()
        except Exception as e:
            print(f"Error listing fleet: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if not args.prompt:
        print(f"Usage: python raen-cli.py {args.service} '<prompt>' [--dry-run]")
        sys.exit(0)

    client = X402Client(
        api_key=args.api_key,
        private_key=privkey,
        dry_run=dry,
        max_amount=args.max_amount,
    )

    print(f"\n{'=' * 64}")
    print(f"  Tool:    {args.service}")
    print(f"  Prompt:  {args.prompt[:75]}{'...' if len(args.prompt) > 75 else ''}")
    print(f"  Mode:    {'DRY-RUN (Simulated)' if dry else 'LIVE SIGNING (Base Mainnet)'}")
    print(f"{'=' * 64}")

    try:
        result = client.call_tool(args.service, {"prompt": args.prompt})
        print(f"\n{'=' * 64}")
        print("  Response:")
        print(f"{'=' * 64}")
        if args.pretty or isinstance(result, dict):
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(result)
        print()
    except RuntimeError as e:
        print(f"\n\x1b[31m\x1b[1mError:\x1b[0m {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
