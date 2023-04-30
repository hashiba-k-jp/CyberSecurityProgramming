from ctypes import *
import socket
import struct
import sys
import os

class IP(Structure):
    # This _fields_ is required by Structure Class to be defined before creating any other objects
    _fields_ = [
        #("<FIELD NAME>", <DATA TYPE>, <BIT LENGTH>)
         ("ver",           c_ubyte,   4),       # Version                   # 4 bit unsigned char
         ("ihl",           c_ubyte,   4),       # Internet Header Length    # 4 bit unsigned char
         ("tos",           c_ubyte,   8),       # Type of Service           # 1 byte unsigned char
                        # included in tos # Explicit Congestion Notification
         ("len",           c_ushort, 16),       # Total Length              # 2 byte unsigned short
         ("id",            c_ushort, 16),       # Identification            # 2 byte unsigned short
         ("offset",        c_ushort, 16),       # Flags & Fragment offset   # 2 byte unsigned short
         ("ttl",           c_ubyte,   8),       # Time To Live              # 1 byte unsigned char
         ("protocol_num",  c_ubyte,   8),       # Protocol                  # 1 byte unsigned char
         ("sum",           c_ushort, 16),       # Header checksum           # 2 byte unsigned short
         ("src",           c_uint32, 32),       # Source address            # 4 byte unsigned int
         ("dst",           c_uint32, 32)        # Destination address       # 4 byte unsigned int
    ]

    def __new__(cls, socket_buffer=None):
        # store inputs buffer to Structure
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # store IP Address
        self.src_address=socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address=socket.inet_ntoa(struct.pack("<L",self.dst))

        # map the number to protocol
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if  os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # パケットの読み込み
            raw_buffer = sniffer.recvfrom(65535)[0]
            # バッファーの最初の20バイトからIP構造体を作成
            ip_header = IP(raw_buffer[0:20])
            # 検出されたプロトコルとホストを出力
            print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

    except KeyboardInterrupt:
        # Windowsの場合はプロミスキャスモードを無効化
        if  os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.206'
    sniff(host)