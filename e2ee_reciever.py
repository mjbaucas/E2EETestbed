from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

import socket
import time
import sys
import json
import base64
import struct

sender_private_key = b"""-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAnjVoEHHoXYVkOB+PN2s5QBfvPCIlraKVXvB+DHvXKI/Wrt7x\nfhi1xmD6pJifVjczegm4Nq3UmDyaI/dVUOvmrJl2KF2G6xc6QIMCyCH4cLs/Trw3\ngS5vDwPQQj0eG9CpwRavMHrXuhUl2GASGh4aoWwxumCC0BIzt9XCpcoo9byD9ios\nECXxkSkwb22sqqkO1d6mL2PiZlK3fsH/3TxUhn7VOggT2ssBrXDjFBTvyllGcPIG\nH1Opt8Wd92APi/90D36XXyUpKdLOdlsRC8ZAgBaj/v/oefTAoMm5G1XUc0Za8vzW\nQRSn7msb9QrCUyWfDgnUzPIYUV7naQ6n43PzBwIDAQABAoIBAAaOxyf7WLrbpxpO\ncJTG/IIEG/X9olsupIthY5An5/S19ZudARyNcKdu6KS+8MfVlOwnj/uwO+ItjOQV\nwfMPPCoGWGf27Hs9JLx80bYy9kXR9R9R3OkdYBwat9yvBNr5TLgEtTFIvj1n2AA+\nhzGO8uKjBfKoQnPWdU9W7HELzqPU4mAxSeFhOFcal/p+DPHdLoeV14X93+q7jIzm\naKIHVO4ybstTlGuMALVXXVpL+HFywuTmPJOoM3GBlJ+E3/Vc69c4LwOnkkg6oP0n\nFhXXfZVSgfhpfhgvBJJ0CHA1xpDDOCKHiNGXt4bfraWLKq0uKXZiznYfBD7Q8X1S\nVHieRikCgYEAwvNt7uHacws5SNgWAAUQpmBRsERf2KwNcPfylUyOKv5q3kkU5Eh7\nC8lMsP7cfVxR6vOEX6hNXRaSx9uRqgNGTRvILmKKNDLEUyZTB9SyHMuuEU9H1gVl\nwArv33PyER3Nxvdu3NmwfHBiXLlchFRNCD5wk5tuiCXOwRswKB3HehkCgYEAz8B4\nSS4w8fuBoypmSZAMwYlyeB/wxlYxLQou4I7kotyHaHmDlW6OUpb//VdMcz0NZ01C\nicd6fIfYlyXLtoKP2zfAMF1JTgol+UiUVdaSJNps4WIp9Y3yBfWumtIbXJAPjvbr\nwZo61bnzZmRcwHvSczsxs1LUVqcvzwOUKgUGuh8CgYEAg8EJVx0FCiNXv8dqdvD1\nY7xM+Rf8vu7o1qR8KjLnEl+H0lsJ546kuj59ulFEquSt6GBT4mJYhsUuxiu6snAs\nHwjbrZ2jUcvNq3SHQQ+aoKN3LPOr1RUowzWhEB/IRZEi9YlcP55QDInXsFsGD9j5\nhszMQLYXaaRDq3a4gSQ/IGECgYA/kV/83GJjmJZpK68SsT4F9h2NfhB5T6RKaMRB\nN9fjsWDJae0GS0bHJKb9iLm+xR6VzkEe0We8NQDj9s+nb7m+1Qc8hT7J3zcRWNDy\nlu4u0prgN94o4Z79jdg4TTPMFdR85TbsDVoVTYmZefobd4fEdIdXnG+WeB+b0zeB\nx/nv9wKBgCRw5lDHI1zKQp97r7Q/6Vuuo2fgAzoZUjXNPtKhv44cvniHCzMgK41S\nTOPjB+Yi/zsbKUh89erJX8OqE3usP+ynNeXVl2X/fm2QY1WNO+kUkwl+EcdOFoYq\nYBs6LWhWyAtVB5k/yRBnmnNHMyYAs5AZE9rBCOdY4J68JFl2cpaI\n-----END RSA PRIVATE KEY-----"""
sender_public_key = b"""-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjVoEHHoXYVkOB+PN2s5\nQBfvPCIlraKVXvB+DHvXKI/Wrt7xfhi1xmD6pJifVjczegm4Nq3UmDyaI/dVUOvm\nrJl2KF2G6xc6QIMCyCH4cLs/Trw3gS5vDwPQQj0eG9CpwRavMHrXuhUl2GASGh4a\noWwxumCC0BIzt9XCpcoo9byD9iosECXxkSkwb22sqqkO1d6mL2PiZlK3fsH/3TxU\nhn7VOggT2ssBrXDjFBTvyllGcPIGH1Opt8Wd92APi/90D36XXyUpKdLOdlsRC8ZA\ngBaj/v/oefTAoMm5G1XUc0Za8vzWQRSn7msb9QrCUyWfDgnUzPIYUV7naQ6n43Pz\nBwIDAQAB\n-----END PUBLIC KEY-----"""
receiver_private_key = b"""-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAmfHnUlJ2D/aatwQ1QVopLyDMOuHI84YfUpZSW4+G+r/R/IUR\n9AAELe9KmgjFnVRbU3hn7hw8oCwFHiQ5jo4aeD6caOJMmJjzQbsDy5JmYXVusEvO\niuS///tdTT+usWsWa189s1h8HvEyUTDXaaYQrwwKS40GJAJxkQ2nrOplpLqe3C4X\ndIPx8lVsRFzqi0+oIL3wDqd7HJuTV/uwGjrs5iMEKQQ1z1Q3oHh+w8WGdzB2uHJI\n843J8pwEy6lgyHSVFFgEAjhUmjo1pZua3MsmuC2wis3BVdiOTO4fcFvUvqk+XEMe\nOBfYK36xTxvlT/zgoIwjShUEmQxj6CEU5339FwIDAQABAoIBABMZ4c2OxRlmoXxz\nPYxgpzAyze8XFCZV46MNWyYDNrNRg7jlEKeJglCUxVk8HLulu43YKG/HTyUXRoHz\n6rRWdiWqAcw9xVVAfRu7HFXGUi+7hhgX1TEvVZIUhVd6vwPtOU3p9lo/cL8sxu/Y\nszxnn4r+CnT6CDiwQ5kaQaOB6J9ksGtUPr2sBdliiRw7KH/RdvYgBwfqBoc+vU8c\n6H3pdnVDKhaJQHrU3foMxl/gsDAHrcg08OVHZNlP3ImFsjmeSRCUAhZiK7XUU2JF\nPHfLFjWSG8P9XNqCpGvx0UfC/J6DpNxiuE23aNbvGItV0y+vwO2BZ1FhcwSDmZgY\nRSmzs9ECgYEAuIUe7XZqnGZoQEc/m2wNM4OeV/bcGIvmpPCUfdXL4mUxboy1EqJ1\nXNm0gtc82NHbFCb0/G6BsY134dkJ3pXm1wsRtu5ivjfMsWZM8lb92LmGfSh+W1pc\nX3zqDC7WBYLKi1k94x+AfMiNceo4RzEBBr7ey0Q277PElm4Qh/M+4hkCgYEA1ZSl\n+G6nb/fQLAReK5G/8ExEkeSSW4E68U4NqfTeuh4/27g5DBChgKLPg5nJf1WazEcL\nJyeBaeZ/rhXiyxQdmnn85Vp4s9dMPnmntS1s6DmDovlASsEqQjqYcTCpNvC5lLGf\nHQxywe7e665FsC+eXLOWdktVlbBnKmkO58pmnq8CgYEAhQv/s+t5jdJNg2OcWp37\nmtRhnT2zj8N4iB+sglthSpn6naK5gXlAtLWJcfputkwC8rHwXf/0ZikCcwfDFQrz\nSsWBfWzAKDYl0xhXjTnqiZWkgqRrD8XE61kvjZ9L1Ods0jOD6zuwsskNLEFdWP/d\npJaGIPzLu+TccDdmlhBvnCkCgYBxgV83CS+IzM1gJy4Yv4ue3Blw42V4pdQ6W33d\nfdpEVUEgtuXyaIA8Ccp4qOkx97+don/l3hPjwPDIBq+Rt24II55oEU2mXdwSM7sS\nCUMgozg3C3nEgKXBrrxHI1I6dXJa+I6T9IKkWBs2a1ZzzMq/f12OHnksZSReoJig\nTKt+1wKBgHGmrbFfZYVERmDuTZ5qMP9rfOXkhifuZlMmBCvwe4KmQbNGvhX5gJDc\nijPHtya/Y2wxjl7JvRGqIL3rcRS7OrrfI9b+/ZiVmI6LBNZbwhDUIqB/Ugcfo9Sn\nJpGm/03HBZTRRUU38VU5VGLY3XrrDsBZWICsbz1YTQP3XzJWUQMs\n-----END RSA PRIVATE KEY-----"""
receiver_public_key = b"""-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmfHnUlJ2D/aatwQ1QVop\nLyDMOuHI84YfUpZSW4+G+r/R/IUR9AAELe9KmgjFnVRbU3hn7hw8oCwFHiQ5jo4a\neD6caOJMmJjzQbsDy5JmYXVusEvOiuS///tdTT+usWsWa189s1h8HvEyUTDXaaYQ\nrwwKS40GJAJxkQ2nrOplpLqe3C4XdIPx8lVsRFzqi0+oIL3wDqd7HJuTV/uwGjrs\n5iMEKQQ1z1Q3oHh+w8WGdzB2uHJI843J8pwEy6lgyHSVFFgEAjhUmjo1pZua3Msm\nuC2wis3BVdiOTO4fcFvUvqk+XEMeOBfYK36xTxvlT/zgoIwjShUEmQxj6CEU5339\nFwIDAQAB\n-----END PUBLIC KEY-----"""

def receiver_verify_and_decrypt(encrypted_aes_key, iv, ciphertext, signature, sender_public_key_pem, receiver_private_key_pem):

    # --- Load keys ---
    sender_key = RSA.import_key(sender_public_key_pem)
    receiver_key = RSA.import_key(receiver_private_key_pem)

    # --- Rebuild payload for verification ---
    payload = encrypted_aes_key + iv + ciphertext
    hash_obj = SHA256.new(payload)

    # --- 1. Verify signature ---
    pss.new(sender_key).verify(hash_obj, signature)

    # --- 2. Decrypt AES key ---
    rsa_cipher = PKCS1_OAEP.new(receiver_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # --- 3. Decrypt data ---
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    return plaintext

counter = 0
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 5000))
    s.listen(5)
    print('Server is now running.')
    connection, address = s.accept()
    print(address)

    raw_len = connection.recv(4)
    msg_len = struct.unpack("!I", raw_len)[0]

    # read full message
    data = b''
    while len(data) < msg_len:
        data += connection.recv(4096)

    json_data = data.decode()
    message = json.loads(json_data)

    encrypted_aes_key = base64.b64decode(message["secret-key"])
    iv = base64.b64decode(message["iv"])
    ciphertext = base64.b64decode(message["data"])
    signature = base64.b64decode(message["signature"])

    plaintext = receiver_verify_and_decrypt(encrypted_aes_key, iv, ciphertext, signature, sender_public_key, receiver_private_key)
    #print(plaintext)
    response = json.dumps({"response": "received"})
    connection.sendall(bytes(str(response), "utf-8"))
    connection.shutdown(socket.SHUT_RDWR)
    connection.close()
        
    print(counter)
    connection.close()