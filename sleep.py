import os
import requests
import mnemonic
import bip32utils
import threading
import base58
from plyer import notification
from colorama import Fore, init
import time

# Initialize colorama
init(autoreset=True)

# Set to store previously generated mnemonic phrases
checked_mnemonics = set()

def generate_entropy(entropy_bits=128):
    return os.urandom(entropy_bits // 8)

def entropy_to_mnemonic(entropy):
    mnemo = mnemonic.Mnemonic("english")
    return mnemo.to_mnemonic(entropy)

def mnemonic_to_seed(mnemonic_phrase, passphrase=""):
    mnemo = mnemonic.Mnemonic("english")
    return mnemo.to_seed(mnemonic_phrase, passphrase)

def generate_master_key(seed):
    return bip32utils.BIP32Key.fromEntropy(seed)

def generate_bip44_wallet(master_key, account=0):
    purpose = 44
    coin_type = 0  # 0 for Bitcoin
    account_key = master_key.ChildKey(purpose + bip32utils.BIP32_HARDEN)
    account_key = account_key.ChildKey(coin_type + bip32utils.BIP32_HARDEN)
    account_key = account_key.ChildKey(account + bip32utils.BIP32_HARDEN)
    return account_key

def get_bitcoin_address(wallet, change=0, address_index=0):
    change_key = wallet.ChildKey(change)
    address_key = change_key.ChildKey(address_index)
    return address_key.Address()

def check_balance_blockstream(address):
    url = f"https://blockstream.info/api/address/{address}"
    retries = 5
    for i in range(retries):
        response = requests.get(url)
        if response.status_code == 200:
            balance_info = response.json()
            return balance_info['chain_stats']['funded_txo_sum'] - balance_info['chain_stats']['spent_txo_sum']
        elif response.status_code in [429, 500, 502, 503, 504]:
            wait_time = (2 ** i) + (i * 0.1)
            print(f"Server error or rate limit exceeded. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
        else:
            response.raise_for_status()
    raise Exception(f"Failed to get balance after {retries} retries")

balance_checkers = [
    check_balance_blockstream
]

def check_balance(address):
    for balance_checker in balance_checkers:
        try:
            return balance_checker(address)
        except Exception as e:
            print(f"Error checking balance with {balance_checker.__name__} for address {address}: {e}")
    return None

def validate_bitcoin_address(address):
    try:
        decoded = base58.b58decode_check(address)
        return decoded[0] == 0
    except Exception:
        return False

def save_wallet_to_file(wallet_info, file_name="wallets_to_recheck.txt"):
    with open(file_name, "a") as file:
        file.write(wallet_info + "\n")

def save_wallet_to_backup(wallet_info, file_name="backup.txt"):
    with open(file_name, "a") as file:
        file.write(wallet_info + "\n")

def send_notification(wallet_info):
    notification.notify(
        title='Bitcoin Wallet with Balance Found!',
        message=wallet_info,
        timeout=25
    )

def generate_and_check_wallet(index):
    while True:
        entropy = generate_entropy()
        mnemonic_phrase = entropy_to_mnemonic(entropy)

        # Check if this mnemonic phrase has already been checked
        if mnemonic_phrase in checked_mnemonics:
            continue

        # Add the mnemonic phrase to the set of checked phrases
        checked_mnemonics.add(mnemonic_phrase)

        seed = mnemonic_to_seed(mnemonic_phrase)
        master_key = generate_master_key(seed)
        bip44_wallet = generate_bip44_wallet(master_key)
        bitcoin_address = get_bitcoin_address(bip44_wallet)

        is_valid = validate_bitcoin_address(bitcoin_address)
        balance = None

        try:
            balance = check_balance(bitcoin_address) if is_valid else None
        except Exception as e:
            wallet_info = (
                f"{Fore.YELLOW}--- Wallet {index + 1} ---{Fore.RESET}\n"
                f"{Fore.CYAN}||| Mnemonic Phrase: {mnemonic_phrase}{Fore.RESET}\n"
                f"{Fore.CYAN}||| Bitcoin Address: {bitcoin_address}{Fore.RESET}\n"
                f"{Fore.CYAN}||| Valid Address: {is_valid}{Fore.RESET}\n"
                f"{Fore.RED}||| Error: {str(e)}{Fore.RESET}\n"
                f"{Fore.YELLOW}-------------------------{Fore.RESET}\n"
            )
            save_wallet_to_backup(wallet_info, "backup.txt")
            print(f"Server error encountered, wallet details saved to backup.txt. Retrying in 10 seconds...")
            time.sleep(10)
            continue

        color = Fore.GREEN if balance and balance > 0 else Fore.RED

        wallet_info = (
            f"{Fore.YELLOW}--- Wallet {index + 1} ---{Fore.RESET}\n"
            f"{Fore.CYAN}||| Mnemonic Phrase: {mnemonic_phrase}{Fore.RESET}\n"
            f"{Fore.CYAN}||| Bitcoin Address: {bitcoin_address}{Fore.RESET}\n"
            f"{Fore.CYAN}||| Valid Address: {is_valid}{Fore.RESET}\n"
            f"{color}||| Balance: {balance}{Fore.RESET}\n"
            f"{Fore.YELLOW}-------------------------{Fore.RESET}\n"
        ) if is_valid else (
            f"{Fore.YELLOW}--- Wallet {index + 1} ---{Fore.RESET}\n"
            f"{Fore.CYAN}||| Mnemonic Phrase: {mnemonic_phrase}{Fore.RESET}\n"
            f"{Fore.CYAN}||| Bitcoin Address: {bitcoin_address}{Fore.RESET}\n"
            f"{Fore.CYAN}||| Valid Address: {is_valid}{Fore.RESET}\n"
            f"{Fore.RED}||| Balance: Invalid address, no balance check{Fore.RESET}\n"
            f"{Fore.YELLOW}-------------------------{Fore.RESET}\n"
        )

        print(wallet_info)

        if is_valid and balance is not None and balance > 0:
            save_wallet_to_file(wallet_info, "wallets_with_balance.txt")
            send_notification(wallet_info)
        elif is_valid:
            save_wallet_to_file(wallet_info, "wallets_to_recheck.txt")

        break

def run_indefinitely(num_wallets):
    index = 0
    while True:
        threads = []
        for i in range(num_wallets):
            thread = threading.Thread(target=generate_and_check_wallet, args=(index,))
            threads.append(thread)
            thread.start()
            index += 1

        for thread in threads:
            thread.join()

num_wallets = 10

run_indefinitely(num_wallets)
