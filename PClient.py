#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import numpy as np
import pickle
import random
import cv2
import Crypto.Hash.MD5 as MD5
import atexit
from collections import defaultdict

USERNAME = ''
LISTENER_SOCK = None
SERVER_SOCKET = None
INPUTS = []  # readable sockets
OUTPUTS = []  # writetable sockets
MSGS = defaultdict(list)  # messages to be sent (queue), indexed by socket
logged_in_users = {}  # ports, indexed by username
sockets = {}  # sockets, indexed by username
ServerPort = 5535
AUTH_STATUS = 'FAIL'


class SteganographyException(Exception):
    pass


class LSBSteg():
    def __init__(self, im):
        self.image = im
        self.height, self.width, self.nbchannels = im.shape
        self.size = self.width * self.height

        self.maskONEValues = [1, 2, 4, 8, 16, 32, 64, 128]
        # Mask used to put one ex:1->00000001, 2->00000010 .. associated with OR bitwise
        # Will be used to do bitwise operations
        self.maskONE = self.maskONEValues.pop(0)

        self.maskZEROValues = [254, 253, 251, 247, 239, 223, 191, 127]
        # Mak used to put zero ex:254->11111110, 253->11111101 .. associated with AND bitwise
        self.maskZERO = self.maskZEROValues.pop(0)

        self.curwidth = 0  # Current width position
        self.curheight = 0  # Current height position
        self.curchan = 0   # Current channel position

    def put_binary_value(self, bits):  # Put the bits in the image
        for c in bits:
            # Get the pixel value as a list
            val = list(self.image[self.curheight, self.curwidth])
            if int(c) == 1:
                val[self.curchan] = int(
                    val[self.curchan]) | self.maskONE  # OR with maskONE
            else:
                val[self.curchan] = int(
                    val[self.curchan]) & self.maskZERO  # AND with maskZERO

            self.image[self.curheight, self.curwidth] = tuple(val)
            self.next_slot()  # Move "cursor" to the next space

    def next_slot(self):  # Move to the next slot were information can be taken or put
        if self.curchan == self.nbchannels-1:  # Next Space is the following channel
            self.curchan = 0
            if self.curwidth == self.width-1:  # Or the first channel of the next pixel of the same line
                self.curwidth = 0
                if self.curheight == self.height-1:  # Or the first channel of the first pixel of the next line
                    self.curheight = 0
                    if self.maskONE == 128:  # Mask 1000000, so the last mask
                        raise SteganographyException(
                            "No available slot remaining (image filled)")
                    else:  # Or instead of using the first bit start using the second and so on..
                        self.maskONE = self.maskONEValues.pop(0)
                        self.maskZERO = self.maskZEROValues.pop(0)
                else:
                    self.curheight += 1
            else:
                self.curwidth += 1
        else:
            self.curchan += 1

    def read_bit(self):  # Read a single bit int the image
        val = self.image[self.curheight, self.curwidth][self.curchan]
        val = int(val) & self.maskONE
        self.next_slot()
        if val > 0:
            return "1"
        else:
            return "0"

    def read_byte(self):
        return self.read_bits(8)

    def read_bits(self, nb):  # Read the given number of bits
        bits = ""
        for i in range(nb):
            bits += self.read_bit()
        return bits

    def byteValue(self, val):
        return self.binary_value(val, 8)

    def binary_value(self, val, bitsize):  # Return the binary value of an int as a byte
        binval = bin(val)[2:]
        if len(binval) > bitsize:
            raise SteganographyException(
                "binary value larger than the expected size")
        while len(binval) < bitsize:
            binval = "0"+binval
        return binval

    def encode_text(self, txt):
        l = len(txt)
        # Length coded on 2 bytes so the text size can be up to 65536 bytes long
        binl = self.binary_value(l, 16)
        self.put_binary_value(binl)  # Put text length coded on 4 bytes
        for char in txt:  # And put all the chars
            c = ord(char)
            self.put_binary_value(self.byteValue(c))
        return self.image

    def decode_text(self):
        ls = self.read_bits(16)  # Read the text size in bytes
        l = int(ls, 2)
        i = 0
        unhideTxt = ""
        while i < l:  # Read all bytes of the text
            tmp = self.read_byte()  # So one byte
            i += 1
            unhideTxt += chr(int(tmp, 2))  # Every chars concatenated to str
        return unhideTxt

    def encode_image(self, imtohide):
        w = imtohide.width
        h = imtohide.height
        if self.width*self.height*self.nbchannels < w*h*imtohide.channels:
            raise SteganographyException(
                "Carrier image not big enough to hold all the datas to steganography")
        # Width coded on to byte so width up to 65536
        binw = self.binary_value(w, 16)
        binh = self.binary_value(h, 16)
        self.put_binary_value(binw)  # Put width
        self.put_binary_value(binh)  # Put height
        for h in range(imtohide.height):  # Iterate the hole image to put every pixel values
            for w in range(imtohide.width):
                for chan in range(imtohide.channels):
                    val = imtohide[h, w][chan]
                    self.put_binary_value(self.byteValue(int(val)))
        return self.image

    def decode_image(self):
        width = int(self.read_bits(16), 2)  # Read 16bits and convert it in int
        height = int(self.read_bits(16), 2)
        # Create an image in which we will put all the pixels read
        unhideimg = np.zeros((width, height, 3), np.uint8)
        for h in range(height):
            for w in range(width):
                for chan in range(unhideimg.channels):
                    val = list(unhideimg[h, w])
                    val[chan] = int(self.read_byte(), 2)  # Read the value
                    unhideimg[h, w] = tuple(val)
        return unhideimg

    def encode_binary(self, data):
        l = len(data)
        if self.width*self.height*self.nbchannels < l+64:
            raise SteganographyException(
                "Carrier image not big enough to hold all the datas to steganography")
        self.put_binary_value(self.binary_value(l, 64))
        for byte in data:
            byte = byte if isinstance(byte, int) else ord(
                byte)  # Compat py2/py3
            self.put_binary_value(self.byteValue(byte))
        return self.image

    def decode_binary(self):
        l = int(self.read_bits(64), 2)
        output = b""
        for i in range(l):
            output += chr(int(self.read_byte(), 2)).encode("utf-8")
        return output


class Server(threading.Thread):

    sock = None

    def init(self, sock):
        self.sock = sock

    def run(self):
        global logged_in_users, AUTH_STATUS
        while True:
            read, write, err = select.select(INPUTS, [], [], 0)
            for sock in read:
                if sock == self.sock:
                    sockfd, addr = self.sock.accept()
                    INPUTS.append(sockfd)
                    print(str(addr))
                    print(INPUTS[-1])
                else:
                    try:
                        msg = sock.recv(4096)
                        if msg == b'':
                            if sock in OUTPUTS:
                                OUTPUTS.remove(sock)
                            INPUTS.remove(sock)
                            MSGS[sock].clear()
                            sock.close()
                        else:
                            decoded_msg = msg # decode here with own private key
                            msg_data = pickle.loads(decoded_msg)
                            msg_content = msg_data.msg  # decode here with socket's public key then with steganography
                            if msg_data.type == 'AMSG':
                                print('[PUBLIC]', msg.name, ': ', msg_content)
                            elif msg_data.type == 'DMSG':
                                print('[PRIVATE]', msg.name, ': ', msg_content)
                            elif msg_data.type == 'ULST':
                                logged_in_users = msg_content
                                print(msg_content)
                                print(logged_in_users)
                            elif msg_data.type == 'OK':                                
                                AUTH_STATUS = 'OK'
                                print(msg_content)
                            elif msg_data.type == 'FAIL':
                                AUTH_STATUS = 'FAIL'
                                print(msg_content)
                            # elif msg_data.type == 'BYE':
                                # do stuff
                            else:
                                print('UNKNOWN MESSAGE TYPE RECEIVED',
                                      msg_data.type)
                    except:
                        continue


class Msg:
    name = ''  # sender name
    port = 0  # used in authenticatiom
    pub_key = ''  # used in authenticatiom
    type = ''  # type of message
    msg = ''  # content of the message
    password = ''  # used in authentication

    def __str__(self):
        out = 'Name : '
        out += self.name
        out += ' Port :'
        out += str(self.port)
        return out


class Client(threading.Thread):
    sock = None

    def init(self):
        global LISTENER_SOCK
        LISTENER_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        LISTENER_SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        LISTENER_SOCK.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        LISTENER_SOCK.setblocking(False)
        port = random.randint(51400, 51500)
        LISTENER_SOCK.bind(('', port))
        LISTENER_SOCK.listen(2)
        INPUTS.append(LISTENER_SOCK)

    def send(self, type, user, text):
        global USERNAME
        msg = Msg()
        msg.name = USERNAME
        msg.type = type
        encoded_text = text  # Encode the message using steganography and own private key
        msg.msg = encoded_text
        encoded_msg = msg  # Encode the message using the recepient's public key
        recepient_socket = None
        if user in sockets.keys():
            recepient_socket = sockets[user]
        else:
            recepient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            recepient_socket.connect(('', logged_in_users[user]))
            sockets[user] = recepient_socket
            INPUTS.append(recepient_socket)
            OUTPUTS.append(recepient_socket)
        MSGS[user].append(encoded_msg)

    def run(self):
        global AUTH_STATUS, USERNAME, SERVER_SOCKET
        server = Server()
        server.daemon = True
        server.init(LISTENER_SOCK)
        server.start()
        handle = handle_connections()
        handle.start()
        SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        SERVER_SOCKET.connect(('', ServerPort))
        INPUTS.append(SERVER_SOCKET)
        OUTPUTS.append(SERVER_SOCKET)
        while AUTH_STATUS == 'FAIL': # Login/SignUp loop
            msg = Msg()
            initialState = input(
                "To login enter 'l' and to sign up enter 's'")
            if(initialState == 's'):
                msg.type = 'REG'
            elif(initialState == 'l'):
                msg.type = 'LOGIN'
            else:
                print('INVALID INPUT')
                continue
            msg.name = input("Enter your name: ")
            USERNAME = msg.name
            msg.password = input("Enter your password: ")
            AUTH_STATUS = 'WAITING'
            MSGS[SERVER_SOCKET].append(msg)
            while AUTH_STATUS == 'WAITING':
                pass
        while True:
            uinput = input('>>')
            uinput = uinput.split(':')
            if len(uinput) < 1 or len(uinput) > 3:
                print('INVALID MESSAGE FORMAT')
                continue
            type = uinput[0].strip()
            if type == 'FTCH':
                show_user_list()
            elif type == 'DMSG':
                if len(uinput) != 3:
                    print('INVALID MESSAGE FORMAT')
                    continue
                if uinput[1].strip() not in logged_in_users.keys():
                    print('USER <' + uinput[1].strip() + '> IS NOT ONLINE')
                    continue
                self.send(type, uinput[1].strip(), uinput[2])
            elif type == 'AMSG':
                if len(uinput) != 2:
                    print('INVALID MESSAGE FORMAT')
                    continue
                for user in logged_in_users.keys():
                    self.send(type, user, uinput[1].strip())
            else:
                print('INVALID MESSAGE FORMAT')


class handle_connections(threading.Thread):
    def run(self):
        while True:
            read, write, err = select.select([], OUTPUTS, [], 0)
            for sock in write:
                while (MSGS[sock] != []):
                    try:
                        msg = pickle.dumps(MSGS[sock].pop(0))
                        sock.sendall(msg)
                    except:
                        continue

def show_user_list():
    global logged_in_users
    print('ONLINE USERS:')
    for user in logged_in_users.keys():
        print(user)

@atexit.register
def clean_exit():
    global AUTH_STATUS, LISTENER_SOCK, SERVER_SOCKET
    msg = Msg()
    msg.type = 'BYE'
    msg.name = USERNAME
    MSGS[SERVER_SOCKET].append(msg)
    try:
        LISTENER_SOCK.shutdown(socket.SHUT_RDWR)
        LISTENER_SOCK.close()
    except:
        print('Failed to exit gracefully')

if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.init()
    cli.start()
