# raen-cli.py — One-file Python x402 Client for the RAEN Fleet

A robust single-file Python CLI that discovers RAEN x402 services, handles EIP-3009 micropayments on Base mainnet (both x402 v1 and v2), and verifies settlement proofs.

## Features

- **Standards-compliant EIP-712 / EIP-3009 signing** via `eth-account`.
- **Verified Keccak-256** and deterministic single-nonce authorization.
- **Support for both x402 v1 (`X-PAYMENT`) and v2 (`PAYMENT-SIGNATURE`)** with case-insensitive HTTP challenge decoding.
- **Safe offline `--dry-run`** mode for simulated inspection without broadcasting signatures or payments.
- **Spending safety cap** (`--max-amount <atomic_units>`) to prevent unexpected charges.
- **Secure key management**: reads from `RAEN_PRIVATE_KEY` environment variable instead of insecure CLI arguments.

## Usage

```bash
# List all fleet services
python raen-cli.py --list

# Test call with dry-run (inspect 402 challenge, no signature broadcast)
python raen-cli.py raen_law_lookup "What is the FCRA dispute timeline?" --dry-run

# Call with real signing on Base mainnet
export RAEN_PRIVATE_KEY=0x...
python raen-cli.py raen_law_lookup "What is the FCRA dispute timeline?"

# With optional spending cap ($0.10 USDC max = 100000 atomic units)
python raen-cli.py raen_law_lookup "FCRA question" --max-amount 100000

# With gateway Bearer key (if you have one)
python raen-cli.py raen_contract_analysis "analyze this contract..." --key <bearer-token> --json
```

## Running Unit Tests

```bash
python -m unittest raen-cli/test_raen_cli.py
```

Tests verify:
- Standard Keccak-256 hashing versus NIST sha3-256
- Recovering signer address from generated EIP-3009 authorization signatures
- Nonce and timestamp consistency between signed digest and serialized payload
- Both x402 v1 and v2 challenge parsing with case-insensitive HTTP headers
- Offline dry-run safety and spending cap enforcement

## Dependencies

- **Zero dependencies** for `--list` and `--help`
- **Single signing dependency**: `pip install eth-account`
