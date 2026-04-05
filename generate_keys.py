from Crypto.PublicKey import RSA

# --- Sender key pair (for signatures) ---
sender_key = RSA.generate(2048)
sender_private_key = sender_key.export_key()
sender_public_key = sender_key.publickey().export_key()
print("sender private key:" + str(sender_private_key))
print("sender public key:" + str(sender_public_key))

# --- Receiver key pair (for encryption) ---
receiver_key = RSA.generate(2048)
receiver_private_key = receiver_key.export_key()
receiver_public_key = receiver_key.publickey().export_key()
print("receiver private key:" + str(receiver_private_key))
print("receiver public key:" + str(receiver_public_key))
