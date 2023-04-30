import socket

target_host = "0.0.0.0"
target_port = 9998

# make socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send data
client.sendto(b"AAABBBCCC", (target_host, target_port))

# recieve data
data, address = client.recvfrom(4096)

print(data.decode('utf-8'))
print(address)

client.close()