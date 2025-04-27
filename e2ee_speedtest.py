import time
import random
import string

#AES, RSA, Twofish
from Cryptodome.Cipher import AES, PKCS1_OAEP, ChaCha20
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes 
from Cryptodome.PublicKey import RSA

#ECC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_text(char_count):
    characters = string.ascii_letters + string.digits + string.punctuation + ' '
    return ''.join(random.choices(characters, k=char_count))

char_counts = [1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000, 10000000]
for i in range(0, len(char_counts)):
    iterations = 10
    aes_rsa = []
    aes_ecc = []
    cha_rsa = []
    cha_ecc = []

    data = generate_text(char_counts[i]).encode('utf-8')
    #data = b'Some Message'
    for j in range(0,iterations):
        # AES + RSA
        aes_key = get_random_bytes(32) #256 bits = 32 Bytes * 8 Bits/Byte
        aes_cipher = AES.new(aes_key, AES.MODE_CBC)
        aes_padded_data = pad(data, AES.block_size)
        
        start = time.perf_counter()
        aes_ciphertext = aes_cipher.encrypt(aes_padded_data)
        end = time.perf_counter()
        aes_elapsed = end-start

        rsa_key = RSA.generate(2048)
        rsa_private_key = rsa_key
        rsa_public_key = rsa_key.publickey()
        rsa_encryptor = PKCS1_OAEP.new(rsa_public_key)
        
        start = time.perf_counter()
        rsa_ciphertext = rsa_encryptor.encrypt(aes_key)
        end = time.perf_counter()
        rsa_elapsed = end-start
        aes_rsa.append(aes_elapsed + rsa_elapsed)
        #print((end-start))

        rsa_decryptor = PKCS1_OAEP.new(rsa_private_key)
        rsa_decryptedtext = rsa_decryptor.decrypt(rsa_ciphertext)
        aes_decipher = AES.new(rsa_decryptedtext, AES.MODE_CBC, aes_cipher.iv)
        decryptedtext = unpad(aes_decipher.decrypt(aes_ciphertext), AES.block_size)
        #print(data)
        #print(decryptedtext)
        
        # AES + ECC
        start = time.perf_counter()
        receiver_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        receiver_public_key = receiver_private_key.public_key()

        sender_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        sender_public_key = sender_private_key.public_key()

        shared_secret_sender = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
        shared_secret_receiver = receiver_private_key.exchange(ec.ECDH(), sender_public_key)

        aes_key_sender = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=None,
            info=b'ecdh-aes',
            backend=default_backend()
        ).derive(shared_secret_sender)

        aes_key_receiver = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecdh-aes',
            backend=default_backend()
        ).derive(shared_secret_receiver)

        aes_cipher = AES.new(aes_key_sender, AES.MODE_CBC)
        aes_padded_data = pad(data, AES.block_size)

        start = time.perf_counter()
        aes_ciphertext = aes_cipher.encrypt(aes_padded_data)
        end = time.perf_counter()
        aes_elapsed = end-start

        start = time.perf_counter()
        signature = sender_private_key.sign(
            aes_key_receiver,
            ec.ECDSA(hashes.SHA256())
        )
        end = time.perf_counter()
        ecc_elapsed = end-start
        aes_ecc.append(aes_elapsed + ecc_elapsed)

        sender_public_key.verify(
            signature,
            aes_key_receiver,
            ec.ECDSA(hashes.SHA256())
        )
        aes_decipher = AES.new(aes_key_receiver, AES.MODE_CBC, aes_cipher.iv)
        decryptedtext = unpad(aes_decipher.decrypt(aes_ciphertext), AES.block_size)
        #print(data)
        #print(decryptedtext)


        # ChaCha20 + RSA

        chacha_key = get_random_bytes(32)
        nonce = get_random_bytes(8)
        chacha_cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
        chacha_padded_data = pad(data, ChaCha20.block_size)

        start = time.perf_counter()
        chacha_ciphertext = chacha_cipher.encrypt(chacha_padded_data)
        end = time.perf_counter()
        cha_elapsed = end-start

        rsa_key = RSA.generate(2048)
        rsa_private_key = rsa_key
        rsa_public_key = rsa_key.publickey()
        rsa_encryptor = PKCS1_OAEP.new(rsa_public_key)
        
        start = time.perf_counter()
        rsa_ciphertext = rsa_encryptor.encrypt(chacha_key)
        end = time.perf_counter()
        rsa_elapsed = end-start
        cha_rsa.append(cha_elapsed + rsa_elapsed)

        rsa_decryptor = PKCS1_OAEP.new(rsa_private_key)
        rsa_decryptedtext = rsa_decryptor.decrypt(rsa_ciphertext)
        chacha_decipher = ChaCha20.new(key=rsa_decryptedtext, nonce=nonce)
        decrypted_padded_data = chacha_decipher.decrypt(chacha_ciphertext)
        decrypted_data = unpad(decrypted_padded_data, ChaCha20.block_size)
        #print(data)
        #print(decryptedtext)

        # ChaCha20 + ECC

        receiver_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        receiver_public_key = receiver_private_key.public_key()

        sender_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        sender_public_key = sender_private_key.public_key()

        shared_secret_sender = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
        shared_secret_receiver = receiver_private_key.exchange(ec.ECDH(), sender_public_key)

        chacha_key_sender = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # ChaCha20-256
            salt=None,
            info=b'ecdh-ChaCha20',
            backend=default_backend()
        ).derive(shared_secret_sender)

        chacha_key_receiver = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecdh-ChaCha20',
            backend=default_backend()
        ).derive(shared_secret_receiver)

        chacha_cipher = ChaCha20.new(key=chacha_key_sender, nonce=nonce)
        chacha_padded_data = pad(data, ChaCha20.block_size)
        
        start = time.perf_counter()
        chacha_ciphertext = chacha_cipher.encrypt(chacha_padded_data)
        end = time.perf_counter()
        cha_elapsed = end-start

        start = time.perf_counter()
        signature = sender_private_key.sign(
            chacha_key_receiver,
            ec.ECDSA(hashes.SHA256())
        )
        end = time.perf_counter()
        ecc_elapsed = end-start
        cha_ecc.append(cha_elapsed + ecc_elapsed)

        sender_public_key.verify(
            signature,
            chacha_key_receiver,
            ec.ECDSA(hashes.SHA256())
        )
        chacha_decipher = ChaCha20.new(key=chacha_key_receiver, nonce=nonce)
        decrypted_padded_data = chacha_decipher.decrypt(chacha_ciphertext)
        decrypted_data = unpad(decrypted_padded_data, ChaCha20.block_size)
        #print(data)
        #print(decryptedtext)
    
    print(char_counts[i])
    print("aes_rsa:")
    for item in aes_rsa:
        print(item)
    print("aes_ecc:")
    for item in aes_ecc:
        print(item)
    print("cha_rsa:")
    for item in cha_rsa:
        print(item)
    print("cha_ecc:")
    for item in cha_ecc:
        print(item)
    