from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from json import loads

file_received_from_alice = 'encrypted.txt'
decrypted_image_file = 'image.jpg'
bob_private_key_file = 'bob_private_key.pem'
alice_verifying_key_file = 'alice_verifying_key.crt'

bob_password = b'bobsecret'

# Open the input file for reading in text format
f = open(file_received_from_alice, 'r')
# Read in the file contents and save them in the local variable input_text
input_text = f.read()
# Close the file
f.close()

# Open the output file for writing in binary format
f = open(decrypted_image_file, 'wb+')
# Write the local variable file_bytes to the file
f.write(file_bytes)
# Close the file
f.close()
