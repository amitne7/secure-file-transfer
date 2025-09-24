# Changelog

## [Unreleased]

### Added
- **Initial Commit**: Set up project structure and added initial files.
- **Hybrid Encryption & Decryption**: Implemented AES (CBC mode) for fast symmetric encryption of image data.
- **RSA Encryption**: Utilized RSA (PKCS1_OAEP) to protect the AES session key.
- **Digital Signature**: 
  - Alice uses ECC private key with SHA3-512 hashing (FIPS-186-3 DSS compliant).
  - Bob verifies Alice’s signature using her ECC public key certificate.
- **Certificate Validation**: Integrated X.509 certificate validation with OpenSSL to ensure both parties use keys issued by a trusted CA.
- **Data Integrity**: Introduced mechanism where if ciphertext is altered, Bob’s signature verification will fail.
- **ReadMe**: Update README file

## [v0.1.0]

### Added
- Add PROGRESSLOG

### Updated
- Update CHANGELOG  
- Update README  




