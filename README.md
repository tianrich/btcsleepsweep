# Bitcoin Sleep & Sweep

This Python script generates Bitcoin addresses using mnemonic phrases, checks their balances, and automatically creates and broadcasts transactions if the balance exceeds a certain threshold.

## Features

- Generate mnemonic phrases of varying lengths (12, 18, or 24 words).
- Derive private keys and corresponding Bitcoin addresses (compressed and uncompressed) from mnemonic phrases.
- Check the balance of generated Bitcoin addresses.
- Automatically create and broadcast transactions if a certain balance threshold is met.
- Save mnemonic phrases of addresses with significant balances to a file.

## Requirements

- Python 3.x
- `mnemonic` library
- `bip32utils` library
- `ecdsa` library
- `requests` library
- `base58` library

## Installation

1. Clone this repository:

```sh
git clone https://github.com/yourusername/bitcoin-address-hunter.git
cd bitcoin-address-hunter
```

2. Install the required libraries:

```sh
pip install mnemonic bip32utils ecdsa requests base58
```

## Usage

Run the script with the following command:

```sh
python sleep.py
```

The script will continuously generate Bitcoin addresses and check their balances. If an address with a balance greater than 0.01 BTC (1,000,000 satoshis) is found, it will create and broadcast a transaction, transferring the balance to a predefined destination address. The mnemonic phrase of such addresses will be saved to `hunted.txt`.

## Script Overview

### Functions

- `generate_mnemonic(word_count=24)`: Generates a mnemonic phrase of specified word count.
- `mnemonic_to_seed(mnemonic)`: Converts mnemonic phrase to seed.
- `derive_private_keys(seed)`: Derives private keys from the seed.
- `private_key_to_wif(private_key_hex)`: Converts a private key to Wallet Import Format (WIF).
- `private_key_to_public_key(private_key, compressed=True)`: Converts a private key to a public key.
- `public_key_to_address(public_key)`: Converts a public key to a Bitcoin address.
- `check_balance(address)`: Checks the balance of a Bitcoin address.
- `create_transaction(private_key_wif, source_address, dest_address, balance)`: Creates a raw Bitcoin transaction.
- `broadcast_transaction(raw_tx)`: Broadcasts a raw transaction to the Bitcoin network.
- `save_to_file(data, filename)`: Saves data to a file.

### Main Function

- The `main()` function generates mnemonic phrases of different lengths, derives private keys and addresses, checks balances, creates and broadcasts transactions if necessary, and saves the mnemonic phrases of addresses with significant balances to `hunted.txt`.

## Important Notes

- This script is for educational purposes only. Use it responsibly and at your own risk.
- Ensure compliance with local laws and regulations when using this script.
- The transaction creation and broadcasting functions are simplified and need actual implementation for real-world usage.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

The author is not responsible for any misuse or damages caused by this script. Use it responsibly and at your own risk.

---

**Donations welcome to: 3KgiK7FdnEHpBDt3uie9mU1QRnVN8sP81o
