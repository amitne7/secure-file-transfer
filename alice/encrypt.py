from Crypto.Hash import SHA3_512
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from json import dumps
from base64 import b64encode
from Crypto.Util.Padding import pad
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, X509Store, X509StoreContext


file_sent_to_bob = '../bob/encrypted.txt'
alice_signing_key_file = 'alice_signing_key.pem'
bob_public_key_file = 'bob_public_key.crt'
ca_certificate = 'ca.crt'
image_file = 'confidential_image.JPG'
password = 'alicesecret'


def read_file(file_name, mode):
    with open(file_name, mode) as file_content:
        return file_content.read()


def encryption():
    alice_signing_key_file_content = read_file(alice_signing_key_file, 'rb')
    alice_private_key = ECC.import_key(alice_signing_key_file_content, passphrase=password)

    bob_public_key_file_content = read_file(bob_public_key_file, 'rb')
    bob_public_key = RSA.import_key(bob_public_key_file_content)

    message = read_file(image_file, 'rb')

    # padded plaintext with block size
    padded_plaintext = pad(message, AES.block_size)
    session_key = get_random_bytes(32)  # Generate session key of 256 bit

    # encrypt padded plaintext using AES CBC mode
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(padded_plaintext)
    iv = cipher_aes.iv

    # Encrypt the session key with Bob's public key
    cipher_rsa = PKCS1_OAEP.new(bob_public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # sign the message with alice private key
    hash_value = SHA3_512.new(message)  # create hash using SHA3_512

    # crating signing object of DSA using FIPS-186-3 and alice
    # private key
    signer = DSS.new(alice_private_key, 'fips-186-3')
    signature = signer.sign(hash_value)

    # create json string by decoding values with base64
    json_string = dumps({
        "signature": b64encode(signature).decode('utf-8'),
        "key": b64encode(encrypted_session_key).decode('utf-8'),
        "ciphertext": b64encode(ciphertext).decode('utf-8'),
        "iv": b64encode(iv).decode('utf-8')
    })
    print('File encrypted successfully!')
    # write json string to file to share with bob
    with open(file_sent_to_bob, 'w+') as encrypted_file:
        encrypted_file.write(json_string)


# validate issued certificate
def validate_certificate():
    root_cert_content = read_file(ca_certificate, 'rb')
    bob_cert_content = read_file(bob_public_key_file, 'rb')

    root_cert = load_certificate(FILETYPE_PEM, root_cert_content)
    bob_cert = load_certificate(FILETYPE_PEM, bob_cert_content)
    store = X509Store()
    store.add_cert(root_cert)
    store.add_cert(bob_cert)
    store_ctx = X509StoreContext(store, bob_cert)
    try:
        store_ctx.verify_certificate()
        encryption()
    except Exception as e:
        print('Error', e)


validate_certificate()
