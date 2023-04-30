import argparse
import locale
import os
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

# get command as cmd, and return output
def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return

    if os.name == "nt": # at Windows # validate 'dir', 'echo', etc...
        shell = True
    else:               # Others
        shell = False

    # check_output := runs command at local operating system
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT, shell=shell)

    if locale.getdefaultlocale() == ('ja_JP', 'cp932'):
        return output.decode('cp932')
    else:
        return output.decode()


class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer

        # generate socket object
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()


    def send(self):
        # connect to specified port number
        self.socket.connect((self.args.target, self.args.port))

        # send if there is a buffer.
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True: # send and receive
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt: # Terminated by CTRL-C
            print('\nUser terminated.')
            self.socket.close()
            sys.exit()
        except EOFError as e:
            print(e)


    def listen(self):
        # bind to the address and specified port number
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            # pass the connected socket to the handle
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket, )
            )
            client_thread.start()


    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break

            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())


        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'<BHP:#> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())

                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''

                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()


if __name__ == "__main__":
    # generate command line interface
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            example:
            # launch interactive shell
            netcat.py -t 192.168.1.108 -p 5555 -l -c
            # upload files
            netcat.py -t 192.168.1.108 -p 5555 -l -u=mytext.txt
            # execute commands
            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\"
            # send strings to port 135 of connected server
            echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135
            # connect to the server
            netcat.py -t 192.168.1.108 -p 5555
        ''')
    )

    parser.add_argument('-c', '--command', action='store_true'     , help='initialize interactive shell')
    parser.add_argument('-e', '--execute',                           help='execute the specified command')
    parser.add_argument('-l', '--listen' , action='store_true'     , help='waiting connection mode')
    parser.add_argument('-p', '--port'   , type=int, default=5555  , help='set the port number')
    parser.add_argument('-t', '--target' , default='192.168.1.203' , help='set the IP address')
    parser.add_argument('-u', '--upload' ,                           help='upload files')

    args = parser.parse_args()
    if args.listen: # if it has been set as LISTENER, launch NetCat object with empty buffer
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()
