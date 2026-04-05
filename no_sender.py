import socket
import time 
import sys
import json

import random
import string
import struct

char_counts = [10000, 100000, 1000000, 5000000, 10000000]

def generate_data(size):
    return ''.join(random.choices(string.ascii_letters, k=size)).encode('utf-8')

averages = []
for i in range(3):
    reset = 1
    start = 0
    total = 0
    counter = 0
    while counter < 10:
        if reset == 1:
            start = time.time()
            reset = 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("192.168.137.1", 5000))
            
            data = generate_data(char_counts[int(sys.argv[1])])
            
            message = json.dumps({
                "data": base64.b64encode(data).decode()
            }).encode()

            s.sendall(struct.pack("!I", len(message)))  # send length
            s.sendall(message)
            
            message = s.recv(4096).decode("utf-8")
                
            if message != "":
                #print(message)
                message = json.loads(message)
                end = time.time()
                elapsed = end-start
                if elapsed > 0:
                    total += elapsed
                    counter += 1
                    print(elapsed)
                    print(total)
                    print(counter)
                    print(total/counter)
                    if counter == 10:
                        averages.append(total/counter)
                reset = 1
            else:
                reset = 0
            s.close()
        except Exception as msg:
            print(msg)
            reset = 0
print(averages)