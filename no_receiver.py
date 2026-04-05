import socket
import time
import sys
import json
import struct

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
    #print(plaintext)
    response = json.dumps({"response": "received"})
    connection.sendall(bytes(str(response), "utf-8"))
    connection.shutdown(socket.SHUT_RDWR)
    connection.close()
        
    print(counter)
    connection.close()