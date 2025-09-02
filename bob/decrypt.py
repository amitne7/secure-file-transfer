from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from json import loads
from base64 import b64decode
from Crypto.Util.Padding import unpad
from OpenSSL.crypto import load_certificate, FILETYPE_PEM, X509Store, X509StoreContext

file_received_from_alice = 'encrypted.txt'
decrypted_image_file = 'image.jpg'
bob_private_key_file = 'bob_private_key.pem'
alice_verifying_key_file = 'alice_verifying_key.crt'
ca_certificates = 'ca.crt'
password = 'bobsecret'


def read_file(file_name, mode):
    with open(file_name, mode) as file_content:
        return file_content.read()


# Decryption using AES using CBC mode
def decryption():
    json_string = read_file(file_received_from_alice, 'r')
    json_object = loads(json_string)

    bob_private_key_file_content = read_file(bob_private_key_file, 'rb')
    private_key = RSA.import_key(bob_private_key_file_content, passphrase=password)

    alice_verify_key_content = read_file(alice_verifying_key_file, 'rb')
    alice_verify_key = ECC.import_key(alice_verify_key_content)

    cipher_text = b64decode(json_object['ciphertext'])
    iv = b64decode(json_object['iv'])
    encrypted_key = b64decode(json_object['key'])
    signature = b64decode(json_object['signature'])

    # decrypt encrypted session key using private key
    cipher_decrypt = PKCS1_OAEP.new(private_key)
    session_key = cipher_decrypt.decrypt(encrypted_key)

    # decrypt cipher text using AES in CBC mode using aes key and iv
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher_aes.decrypt(cipher_text)

    # un pad plaintext
    plaintext = unpad(padded_plaintext, AES.block_size)

    # get hash value and verifier using alice verifying key
    hash_value = SHA3_512.new(plaintext)
    verifier = DSS.new(alice_verify_key, 'fips-186-3')
    try:
        verifier.verify(hash_value, signature)
        print('File decrypted successfully!')
        with open(decrypted_image_file, 'wb+') as op:
            op.write(plaintext)
    except ValueError:
        print("Invalid signature. data may altered")


def validate_certificate():
    ca_content = read_file(ca_certificates, 'rb')
    alice_cert_content = read_file(alice_verifying_key_file, 'rb')

    root_cert = load_certificate(FILETYPE_PEM, ca_content)
    bob_cert = load_certificate(FILETYPE_PEM, alice_cert_content)
    store = X509Store()
    store.add_cert(root_cert)
    store.add_cert(bob_cert)
    store_ctx = X509StoreContext(store, bob_cert)
    try:
        store_ctx.verify_certificate()
        decryption()
    except Exception as e:
        print('Error', e)


validate_certificate()
