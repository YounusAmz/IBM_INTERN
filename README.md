Steganography

Image Steganography with Password Protection

This project allows you to hide secret messages inside images and decrypt them securely using a password

Features Encrypt text inside PNG JPG and JPEG images Secure encryption with a password hash Decrypt messages only with the correct password Simple GUI interface using Tkinter

How It Works

Encryption Select an image Enter your secret message Set a password Save the encrypted image

Decryption Select the encrypted image Enter the password Retrieve the hidden message

Requirements Python tkinter Pillow stegano hashlib os

Usage Run the encryption or decryption script

python encrypt py To hide a message python decrypt py To reveal the message

Notes The correct password is required to decrypt the message JPG JPEG images are converted to PNG for better encryption
