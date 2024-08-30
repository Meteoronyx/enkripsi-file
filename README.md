# Enkripsi dan Dekripsi File

Script ini berfungsi untuk mengenkripsi dan atau mendekripsi file pada suatu folder, menggunakan algoritma AES yang terintegrasi dengan telegram untuk mengirimkan kunci enkripsi dan id untuk identifikasi.

Script ini juga menghashing nama file menggunakan algoritma bcrypt yang diberikan salt. Nama file dapat dikembalikan ke bentuk semula karena hashing bcrypt hanya dijadikan penandaan, nama file yang terenkripsi menyimpan salinannya secara terpisah dalam blok data yang juga dienkripsi

# Getting Started
## Requirements

```bash
pip install -r requirements.txt
```


## Installation

1. Clone the repository

```python
git clone https://github.com/Meteoronyx/enkripsi-file
```
2. Navigate to the project directory
```python
cd enkripsi-file
```

## Configuration

Update the bot_token and chat_id in main2.py with your Telegram bot token and chat ID:
```python
bot_token = 'YOUR_BOT_TOKEN'
chat_id = 'YOUR_CHAT_ID'
```

## Usage

### Encrypting Files
Run the script and follow the prompts to encrypt a folder:
```python
python main2.py
Choose E for encryption.
Provide the path to the folder you wish to encrypt.
```

### Decrypting Files
Run the script and follow the prompts to encrypt a folder:
```python
python main2.py
Choose D for decryption.
Provide the path to the folder you wish to decrypt.
Enter the secret key from your telegram in hexadecimal format when prompted.
```
