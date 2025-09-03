# Secure Image Encryption, Decryption, and Signature Verification

This repository demonstrates an **end-to-end secure communication workflow** between Alice and Bob:
- **Alice encrypts a confidential image** using hybrid encryption (AES + RSA), signs it using ECC + SHA3-512, and validates Bob’s certificate.
- **Bob decrypts the image**, validates Alice’s certificate, and verifies her digital signature to ensure data integrity.

---

## Features

- **Hybrid Encryption & Decryption**
  - AES (CBC mode) for fast symmetric encryption of image data.
  - RSA (PKCS1_OAEP) to protect the AES session key.
- **Digital Signature**
  - Alice uses ECC private key with SHA3-512 hashing (FIPS-186-3 DSS compliant).
  - Bob verifies Alice’s signature using her ECC public key certificate.
- **Certificate Validation**
  - X.509 certificate validation with OpenSSL.
  - Ensures both parties use keys issued by a trusted CA.
- **Data Integrity**
  - If ciphertext is altered, Bob’s signature verification will fail.

---
## How It Works

1. **Certificate Validation (Both Sides)**  
   - Ensures certificates (`bob_public_key.crt` and `alice_verifying_key.crt`) are issued by `ca.crt`.
   - If validation fails, the process stops.

2. **Alice’s Encryption Process**  
   - Pads the image to AES block size.  
   - Generates a random 256-bit AES session key.  
   - Encrypts the image with AES (CBC mode).  
   - Encrypts the AES session key using Bob’s RSA public key.  
   - Signs the original image using Alice’s ECC private key and SHA3-512.  
   - Outputs Base64-encoded JSON containing:  
     - `signature`  
     - `key` (encrypted AES session key)  
     - `ciphertext` (AES encrypted image)  
     - `iv` (AES initialization vector)

3. **Bob’s Decryption and Verification Process**  
   - Decrypts AES session key using Bob’s RSA private key.  
   - Decrypts image ciphertext using AES (CBC mode).  
   - Removes PKCS#7 padding to recover original image.  
   - Verifies Alice’s signature using her ECC public key certificate.  
   - If signature fails, the file is considered **tampered**.

---

## Prerequisites
    -  Python 3.x

### Required libraries
    -  pip install pycryptodome pyopenssl
    
### Output will be written to
    - ../bob/encrypted.txt 
    
### If signature is valid, output image is saved as:
    - image.jpg
