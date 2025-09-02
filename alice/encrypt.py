from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
image_file = 'confidential_image.JPG'
file_sent_to_bob = '../bob/encrypted.txt'
alice_signing_key_file = 'alice_signing_key.pem'
bob_public_key_file = 'bob_public_key.crt'

alice_signing_key_password = b'alicesecret'

with open(alice_signing_key_file, 'rb') as key_pair:
    private_key = RSA.import_key(key_pair.read(), alice_signing_key_password)
    pk = private_key.export_key('OpenSSH')
print(pk)
# # Open the input file for reading in binary format
# f_open = open(bob_public_key_file, 'rb')
# f_key = f_open.read()
# f_open.close()
# f = open(image_file, 'rb')
# input_bytes = f.read()
# f.close()
# #print(input_bytes)
# key_pair = RSA.import_key(f_key)
# public_key = key_pair.export_key('OpenSSH')
# print(public_key)
# if isinstance(key_pair, RSA.RsaKey):
#     print("RSA public key")
# else:
#     print("Other key")
# # Open the output file for writing in text format
# #f = open(file_sent_to_bob, 'w+')
# # Write the local variable output_text to the file
# #f.write(output_text)
# # Close the file
# #f.close()
