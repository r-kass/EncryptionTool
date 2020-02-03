#!/usr/bin/env python

from Crypto.Cipher import AES
import hashlib
import binascii
import os
import hmac
import base64

#  File : encryptionTool.py
#  Author: Ruby Kassala
#  Last Modified: 2017.02.21
#
#  Description: Encryptor+Decryptor
#               Takes input from console to encrypt and encrypts string.
#               Also decrypts same string after checking for validity.
#               Output is saved as a .txt file as well as printed to
#               the console for quick access.
#

# takes in user input for password
# input string must be multiple of 16
password = raw_input("Please enter a password: ")

message = raw_input("Please enter a message: ")
paddinglen = 16 - (len(message) % 16)
message += chr(paddinglen)*paddinglen


# open output file to allow writing to file
outfile = open('output.txt', 'w')
salt = os.urandom(32) # sufficiently secure if not used frequently
km = hashlib.pbkdf2_hmac('sha512', password, salt, 100000)

# uses sha-512 HMAC
# uses first 32 bytes or 256 bits as keys
ke = hmac.new(km, 'Encryption Salt', hashlib.sha512).digest()[0:32]
kh = hmac.new(km, 'Hash Salt', hashlib.sha512).digest()[0:32]

# cryptographically random
# block size equal to AES-256 encryption
iv = os.urandom(16)

# use encrypt function to encrypt input using
# AES 256, iv, and ke, with CBC chaining mode
encTool = AES.new(ke, AES.MODE_CBC, iv)
encryptedText = encTool.encrypt(message)

#encryptedTextLen = 16 - (len(encryptedText) % 16)
#encryptedText += chr(encryptedTextLen)*encryptedTextLen

print("Encrypted text: ", encryptedText)
outfile.write(encryptedText)

# ----------IMPLEMENTATAION FOR TAKING USER INPUT------------

# password = raw_input("Please enter the same password: ")
# #pass_len = 16 - (len(password) % 16)
# #password += chr(pass_len)*pass_len
#
# encryptedText = raw_input("Please enter the encrypted string: ")
# #encryptedTextLen = 16 - (len(encryptedText) % 16)
# #encryptedText += chr(encryptedTextLen)*encryptedTextLen
# ----------IMPLEMENTATAION FOR TAKING USER INPUT------------

# generate HMAC of iv and encrypted
# message using kh as secret
msgAuthCode = hmac.new(kh, iv + encryptedText, hashlib.sha512).digest()

#decrypt everything
km_decrypt = hashlib.pbkdf2_hmac('sha512', password, salt, 100000)
ke_decrypt = hmac.new(km_decrypt, 'Encryption Salt', hashlib.sha512).digest()[0:32]
kh_decrypt = hmac.new(km_decrypt, 'Hash Salt', hashlib.sha512).digest()[0:32]

#check if decrypted password is a match
validate = hmac.new(kh_decrypt, iv + encryptedText, hashlib.sha512).digest()

#uncomment the line below if you would like to validate that passwords match
#print hmac.compare_digest(msgAuthCode, validate)

decTool = AES.new(ke_decrypt, AES.MODE_CBC, iv)
plaintext = decTool.decrypt(encryptedText) #get plaintext back

if (hmac.compare_digest(msgAuthCode, validate) == True): #if encryption/decription was success
    outfile.write(base64.b64encode(base64.b64encode(salt)))
    outfile.write(base64.b64encode(base64.b64encode(msgAuthCode)))
    outfile.write(base64.b64encode(base64.b64encode(iv)))
    outfile.write(plaintext)

    print("Salt: ", base64.b64encode(base64.b64encode(salt)))
    print("HMAC: ", (base64.b64encode(base64.b64encode(msgAuthCode))))
    print("IV: ", (base64.b64encode(base64.b64encode(iv))))
    print("Plaintext: ", plaintext) #sorry for ugly formatting, had to be multiple of 16

else: #else tool failed
    print ("encryption/decryption error: the message is corrupts")
