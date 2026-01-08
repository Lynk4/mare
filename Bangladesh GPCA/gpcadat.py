#!/usr/bin/python3

# Task 4 
# - common decryption
# - identifying the crypto algorithm
# - using a decoding framework 

from decoder_core import *
from Crypto.Cipher import AES, Salsa20, ARC2, ARC4, Blowfish, DES3, DES

class Decoder(TrainingDecoder):
    def __init__(self):
        # MD5 hash of the correctly decrypted file
        super().__init__()

    def decode(self):
        # self.data is a bytearray with the contents of the file

        # 1. Insert the key as a hexadecimal string:
        key = bytes.fromhex("4E381FA77F08CCAA0D56EDEFF9ED08EF")

        # 2. Identify the decryption algorithm and use it
        # examples:
        # cipher = AES.new(key, AES.MODE_EAX)
        # cipher = ARC4.new(key)
        # cipher = Salsa20.new(key=key)
        # cipher = ARC2.new(key, ARC2.MODE_CFB)
        # cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        # cipher = DES3.new(key, DES3.MODE_CFB)
        # cipher = DES.new(key, DES.MODE_OFB)
        cipher = ARC4.new(key) # <-- Create a proper decryption class here

        # If you use the correct algorithm and the key, the decrypted data will be written
        # in a .dec file
        self.data = cipher.decrypt(bytes(self.data))

        # Check if the results are correct
        self.check_results()

# Create the decryptor object. Automation happens in __init__()
Decoder()

