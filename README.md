# IBM_INTERN

Image Steganography: Encrypt & Decrypt Secret Messages

This project allows users to hide secret messages inside an image and retrieve them using a password-based decryption system.

Features

✅ Hide a secret message inside an image using a password.
✅ Retrieve the message only with the correct password.
✅ Uses image steganography for secure message encoding.
✅ Supports any JPEG/PNG image as a carrier.

How It Works


1. Encryption (encrypt.py)

User enters a secret message and password.

The message is hidden inside an image (Authentic.jpg).

The encoded image is saved as encryptedImage.jpg.



2. Decryption (decrypt.py)

The program extracts the message from encryptedImage.jpg.

User enters the password to decrypt the message.

If the password matches, the secret message is displayed.




