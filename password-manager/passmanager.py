import argparse
import os
import random
import string

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import json

# File to store encrypted passwords
PASSWORD_FILE = 'passwords.enc'


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_data(key: bytes, data: str) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_data)


def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()


def generate_complex_password(simple_password: str, name: str) -> str:
    salt = os.urandom(16)
    key = derive_key(simple_password, salt)
    return encrypt_password(key, name).decode()


def encrypt_password(key: bytes, data: str) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Generate a random length that is at least as long as the IV
    random_length = random.randint(len(iv), len(iv) + len(encrypted_data))
    return base64.b64encode(iv + encrypted_data)[:random_length]


def load_passwords(simple_password: str) -> dict:
    if not os.path.exists(PASSWORD_FILE):
        return {}

    with open(PASSWORD_FILE, 'rb') as file:
        encrypted_data = file.read()
        salt = encrypted_data[:16]
        key = derive_key(simple_password, salt)
        try:
            data = decrypt_data(key, encrypted_data[16:])
            return json.loads(data)
        except Exception:
            raise ValueError("Incorrect password or corrupted file.")


def save_passwords(simple_password: str, passwords: dict):
    salt = os.urandom(16)
    key = derive_key(simple_password, salt)
    data = json.dumps(passwords)
    encrypted_data = encrypt_data(key, data)

    with open(PASSWORD_FILE, 'wb') as file:
        file.write(salt + encrypted_data)


def add_new_password(args):
    passwords = load_passwords(args.key)
    complex_password = generate_complex_password(args.key, args.newpass)
    passwords[args.newpass] = {'password': complex_password, 'comment': args.c}
    save_passwords(args.key, passwords)
    print(f"Password for '{args.newpass}' added.")


def show_passwords(args):
    passwords = load_passwords(args.key)
    for name, details in passwords.items():
        print(f"Name: {name}, Password: {details['password']}, Comment: {details['comment']}")


def select_password(args):
    passwords = load_passwords(args.key)
    if args.sel in passwords:
        details = passwords[args.sel]
        print(f"Password: {details['password']}, Comment: {details['comment']}")
    else:
        print("Password not found.")


def update_password(args):
    passwords = load_passwords(args.key)
    if args.update in passwords:
        complex_password = generate_complex_password(args.key, args.update)
        passwords[args.update]['password'] = complex_password
        save_passwords(args.key, passwords)
        print(f"Password for '{args.update}' updated.")
    else:
        print("Password not found.")


def delete_password(args):
    passwords = load_passwords(args.key)
    if args.delete in passwords:
        del passwords[args.delete]
        save_passwords(args.key, passwords)
        print(f"Password for '{args.delete}' deleted.")
    else:
        print("Password not found.")


def main():
    parser = argparse.ArgumentParser(description='Password Manager Tool')
    parser.add_argument('--newpass', type=str, help='Name of the new password')
    parser.add_argument('-c', type=str, help='Comment for the new password')
    parser.add_argument('--key', type=str, required=True, help='Simple password (key)')
    parser.add_argument('--showpass', action='store_true', help='Show all passwords')
    parser.add_argument('--sel', type=str, help='Select a password by name')
    parser.add_argument('--update', type=str, help='Update a password by name')
    parser.add_argument('--delete', type=str, help='Delete a password by name')
    args = parser.parse_args()

    if args.newpass and args.c:
        add_new_password(args)
    elif args.showpass:
        show_passwords(args)
    elif args.sel:
        select_password(args)
    elif args.update:
        update_password(args)
    elif args.delete:
        delete_password(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()