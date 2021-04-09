#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from argparse import ArgumentParser
import sys


class Argparser(ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write(f"\nError: {message}\n")
        sys.exit(2)


def parse_args():
    argparser = Argparser()
    subparsers = argparser.add_subparsers(help='Subparsers for Fpublicity KShare')
    encrypt_subparser = subparsers.add_parser('encrypt', help='Using this subparser you can encrypt your Fpublicity room key')
    encrypt_subparser.add_argument('-puk', '--public-key', type=str, required=True, help="File containing RSA-4096 Public key to encrypt Fpublicity room key file")
    encrypt_subparser.add_argument('-f', '--file', type=str, required=True, help="Fpublicity room key file to be encrypted by RSA-4096 public-key")
    decrypt_subparser = subparsers.add_parser('decrypt', help='Using this subparser you can decrypt your Fpublicity room key')
    decrypt_subparser.add_argument('-prk', '--private-key', required=True, type=str, help="File containing RSA-4096 Private key to decrypt Fpublicity room key file")
    decrypt_subparser.add_argument('-f', '--file', type=str, required=True, help="Fpublicity room key file to be decrypted by RSA-4096 private-key")
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
# AES-256 Encryption using key and iv
# fpub_key = get_fpub_key('fpub_key.bin')
# print("Encypting fpub key with AES-256...")
# aes256_key = generate_AES_key(32)
# print(aes256_key)
# aes256_cipher = AESCipher(aes256_key)
# print(aes256_cipher.iv)
# encoded_fpub_key = aes256_cipher.encrypt(fpub_key)
# with open('fpub_key.aes', 'wb') as f:
#     f.write(encoded_fpub_key)
# with open('fpub_key.aes', 'rb') as f:
#     encoded_fpub_key = f.read()
# iv = aes256_cipher.iv
# aes256_cipher = AESCipher(aes256_key, iv)
# print(aes256_cipher.iv)
# init_fpub_key = aes256_cipher.decrypt(encoded_fpub_key)
# with open('fpub_transOK_key.bin', 'wb') as f:
#     f.write(init_fpub_key)
# print(fpub_key == init_fpub_key)


# Generating RSA-4096 and Ecrypting some bytes (turn to LSB 48 of key.aes. AES 32+16 (key, iv))
# print("Generating RSA 4096...")
# pr_key, pu_key = generate_RSA_pair(4096)
# print("Private is Public")
# cipher = PKCS1_OAEP.new(key=pu_key)
# decrypt = PKCS1_OAEP.new(key=pr_key)
# for i in range(2):
#     cipher_text = cipher.encrypt(b"\x01"*48)
#     print(cipher_text)
#     print(decrypt.decrypt(cipher_text))
    

# Exporting keys
# export_RSA_key(pr_key, 'private.pem')
# export_RSA_key(pu_key, 'public.pem')
# pr_key = RSA.import_key(open('rsa_pr.pem', 'r').read())
# pu_key = RSA.import_key(open('rsa_pu.pem', 'r').read())
# print("Done")
