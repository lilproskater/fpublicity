#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from argparse import ArgumentParser
from os import path
import sys


class Argparser(ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write(f"\nError: {message}\n")
        sys.exit(2)


def parse_args():
    argparser = Argparser()
    if len(sys.argv) < 2:
        argparser.print_help()
        exit()
    subparsers = argparser.add_subparsers(help='Subparsers for Fpublicity KShare')
    rsa_subparser = subparsers.add_parser('rsa-4096', help="Using this subparser you can generate RSA-4096 key pair")
    rsa_subparser.add_argument('-puk', '--public-key', type=str, help="Output Public Key file. [Default: rsa4096_puk.pem]", default="rsa4096_puk.pem")
    rsa_subparser.add_argument('-prk', '--private-key', type=str, help="Output Private Key file. [Default: rsa4096_prk.pem]", default="rsa4096_prk.pem")
    encrypt_subparser = subparsers.add_parser('encrypt', help='Using this subparser you can encrypt your Fpublicity room key')
    encrypt_subparser.add_argument('-puk', '--public-key', type=str, required=True, help="File containing RSA-4096 Public key to encrypt Fpublicity room key file")
    encrypt_subparser.add_argument('-f', '--file', type=str, required=True, help="Fpublicity room key file to be encrypted by RSA-4096 public-key")
    encrypt_subparser.add_argument('-o', '--output', type=str, help="Encrypted fpublicity room key file name. [Default: fpub_key.crypt]", default="fpub_key.crypt")
    decrypt_subparser = subparsers.add_parser('decrypt', help='Using this subparser you can decrypt your Fpublicity room key')
    decrypt_subparser.add_argument('-prk', '--private-key', required=True, type=str, help="File containing RSA-4096 Private key to decrypt Fpublicity room key file")
    decrypt_subparser.add_argument('-f', '--file', type=str, required=True, help="Fpublicity room key file to be decrypted by RSA-4096 private-key")
    decrypt_subparser.add_argument('-o', '--output', type=str, help="Decrypted fpublicity room key file name. [Default: fpub_key.bin]", default="fpub_key.bin")
    return argparser.parse_args()


class AESCipher():
    def __init__(self, key, iv=None):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        self.iv = self.cipher.iv
        self.bit_size = len(self.key) * 8

    def encrypt(self, file_bytes):
        return self.cipher.encrypt(pad(file_bytes, AES.block_size))

    def decrypt(self, file_bytes):
        return unpad(self.cipher.decrypt(file_bytes), AES.block_size)


def generate_RSA_pair(size=4096):
    private_key = RSA.generate(size)
    public_key = private_key.publickey()
    return private_key, public_key


def export_RSA_key(key, file_path):
    key_pem = key.export_key().decode()
    with open(file_path, 'w') as f:
        f.write(key_pem)


def generate_AES_key(size=32):  # 32 bytes - AES256
    return get_random_bytes(size)


def get_fpub_key(file_path):
    with open(file_path, 'rb') as f:
        key = f.read()
    return key


args = parse_args()
if sys.argv[1] == 'rsa-4096':
    pr_key_file = args.private_key
    pu_key_file = args.public_key
    if path.isfile(pr_key_file):
        if input(f'File: "{pr_key_file}" already exists. Overwrite? (y/n): ').lower() != 'y':
            exit()
    if path.isfile(pu_key_file):
        if input(f'File: "{pu_key_file}" already exists. Overwrite? (y/n): ').lower() != 'y':
            exit()
    # Generating RSA-4096
    print("Generating RSA-4096 key pair...")
    pr_key, pu_key = generate_RSA_pair(4096)
    export_RSA_key(pr_key, pr_key_file)
    export_RSA_key(pu_key, pu_key_file)
    print("RSA-4096 generation: OK")
elif sys.argv[1] == 'encrypt':
    file = args.file
    output_file = args.output
    pu_key_file = args.public_key
    if not path.isfile(file):
        exit(f'Error: Could not find file "{file}"')
    if not path.isfile(pu_key_file):
        exit(f'Error: Could not find file "{pu_key_file}"')
    if path.isfile(output_file):
        if input(f'File: "{output_file}" already exists. Overwrite? (y/n): ').lower() != 'y':
            exit()
    try:
        print(f'Getting RSA-4096 Public key from "{pu_key_file}"...')
        pu_key = RSA.import_key(open(pu_key_file, 'r').read())
        if pu_key.has_private():  # if key is Private
            exit(f'Error: Given key is Private. For encrypting Public key is required')
        rsa_cipher = PKCS1_OAEP.new(key=pu_key)
    except ValueError:
        exit(f'Error: File "{pu_key_file}" is not a valid RSA key')
    # AES-256 Encryption using key and iv
    fpub_key = get_fpub_key(file)
    print(f"Encypting {file} with AES-256...")
    aes256_key = generate_AES_key(32)
    aes256_cipher = AESCipher(aes256_key)
    fpub_key = aes256_cipher.encrypt(fpub_key)
    print(f'Encrypting AES-256 key with "{pu_key_file}"...')
    aes256_key = rsa_cipher.encrypt(aes256_key + aes256_cipher.iv)
    with open(output_file, 'wb') as f:
        f.write(fpub_key + aes256_key)
    print(f'"{file}" key encryption: OK')
elif sys.argv[1] == 'decrypt':
    file = args.file
    output_file = args.output
    pr_key_file = args.private_key
    if not path.isfile(file):
        exit(f'Error: Could not find file "{file}"')
    if not path.isfile(pr_key_file):
        exit(f'Error: Could not find file "{pr_key_file}"')
    if path.isfile(output_file):
        if input(f'File: "{output_file}" already exists. Overwrite? (y/n): ').lower() != 'y':
            exit()
    try:
        print(f'Getting RSA-4096 Private key from "{pr_key_file}"...')
        pr_key = RSA.import_key(open(pr_key_file, 'r').read())
        if not pr_key.has_private():  # if key is Public
            exit(f'Error: Given key is Public. For decrypting Private key is required')
        rsa_cipher = PKCS1_OAEP.new(key=pr_key)
    except ValueError:
        exit(f'Error: File "{pr_key_file}" is not a valid RSA key')
    # Decrypting AES-256 key with RSA-4096 private key
    encrypted_fpub_key = get_fpub_key(file)
    print(f'Decrypting AES-256 key using "{pr_key_file}" file...')
    try:
        aes256_key = rsa_cipher.decrypt(encrypted_fpub_key[-512:])
        iv = aes256_key[-16:]
        aes256_key = aes256_key[:-16]
        encrypted_fpub_key = encrypted_fpub_key[:-512]
    except ValueError as e:
        if e.args[0] == "Incorrect decryption.":
            exit(f'Error: AES-256 key decryption error. Invalid Private key "{pr_key_file}" or "{file}" file')
        elif e.args[0] == 'Ciphertext with incorrect length.':
            exit(f'Error: Encrypted AES-256 key cannot be found in "{file}" file')
    # AES-256 Decryption using key and iv
    print(f'Decrypting "{file}" using AES-256 key...')
    aes256_cipher = AESCipher(aes256_key, iv)
    fpub_key = aes256_cipher.decrypt(encrypted_fpub_key)
    with open(output_file, 'wb') as f:
        f.write(fpub_key)
    print(f'"{file}" key decryption: OK')

