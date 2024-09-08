from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import argparse


def key_derivation(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    key = key_derivation(password, salt)
    iv = os.urandom(16)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)


def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        data = f.read()
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]

    key = key_derivation(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)


def main():
    parser = argparse.ArgumentParser(description="File Encryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Select mode: 'encrypt' or 'decrypt'")
    parser.add_argument("input_file", help="Input file path")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("-p", "--password", help="Encryption/Decryption password")

    args = parser.parse_args()

    if not args.password:
        args.password = input("Enter password: ")

    if args.mode == "encrypt":
        encrypt_file(args.input_file, args.output_file, args.password)
        print("File encrypted successfully.")
    elif args.mode == "decrypt":
        decrypt_file(args.input_file, args.output_file, args.password)
        print("File decrypted successfully.")

if __name__ == "__main__":
    main()
