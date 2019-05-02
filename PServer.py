#! /usr/bin/env python

import socket
import sys
import traceback
import threading
# import thread
import select
import json
import pickle
import cv2
import Crypto
import numpy as np
import atexit
from collections import defaultdict

user_list_path = 'user_list.lst'
INPUTS = []  # readable sockets
OUTPUTS = []  # writetable sockets
MSGS = defaultdict(list)  # messages to be sent (queue), indexed by socket
Users = {}  # user objects, indexed by username
logged_in_users = {}  # ports, indexed by username


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

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.setblocking(False)
        self.sock.bind(('', 5535))
        self.sock.listen(2)
        INPUTS.append(self.sock)
        print("Server started on port 5535")

    def run(self):
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
                            MSGS[sock].append(msg)
                            if sock not in OUTPUTS:
                                OUTPUTS.append(sock)
                    except:
                        continue


class Msg:
    name = ''
    port = 0
    pub_key = ''
    type = ''
    msg = ''
    users = []
    password = ''


class User:
    name = ''
    port = None
    pub_key = ''
    password = ''


class handle_connections(threading.Thread):
    def run(self):
        while True:
            read, write, err = select.select([], OUTPUTS, [], 0)
            for sock in write:
                while (MSGS[sock] != []):
                    msg = pickle.loads(MSGS[sock].pop(0))
                    print(msg.type, "MESSAGE TYPE")
                    if(msg.type == 'REG'):
                        if(msg.name not in Users.keys()):
                            print('USER REGISTERATION')
                            user = User()
                            user.name = msg.name
                            user.port = sock.getpeername()[1]
                            user.password = msg.password
                            print(user.name, "NEW USER")
                            Users[user.name] = user
                            logged_in_users[user.name] = user.port
                            response = Msg()
                            response.type = 'OK'
                            response.msg = 'Signed up successfully'
                            try:
                                sock.send(pickle.dumps(response))
                            except:
                                continue
                        else:
                            print('User Already Exists')
                            response = Msg()
                            response.type = 'FAIL'
                            response.msg = 'Username Already Taken'
                            try:
                                sock.send(pickle.dumps(response))
                            except:
                                continue
                    elif (msg.type == 'LOGIN'):
                        if (msg.name in Users.keys() and Users[msg.name].password == msg.password and msg.name not in logged_in_users.keys()):
                            print('User logged in successfully', msg.name)
                            Users[msg.name].port = sock.getpeername()[1]
                            logged_in_users[msg.name] = sock.getpeername()[1]
                            response = Msg()
                            response.type = 'OK'
                            response.msg = 'Signed in successfully'
                            try:
                                sock.send(pickle.dumps(response))
                            except:
                                continue
                        else:
                            print('Invalid username/password', msg.name)
                            response = Msg()
                            response.type = 'FAIL'
                            response.msg = 'Invalid username/password'
                            try:
                                sock.send(pickle.dumps(response))
                            except:
                                continue
                    elif (msg.type == 'FTCH'):
                        print('Userlist requested', msg.name)
                        response = Msg()
                        response.msg = logged_in_users
                        response.type = 'ULST'
                        try:
                            sock.send(pickle.dumps(response))
                        except:
                            continue
                    elif (msg.type == 'BYE'):
                        if logged_in_users[msg.name]:
                            Users[msg.name].socket = None
                            del logged_in_users[msg.name]
                            print('User', msg.name, 'logged out')
                        try:
                            INPUTS.remove(sock)
                            OUTPUTS.remove(sock)
                            sock.shutdown(socket.SHUT_RDWR)
                            sock.close()
                            MSGS[sock].clear()
                            break  # discard any messages to be sent to this user
                        except:
                            continue
                    else:
                        print('Unknown message type', msg.type)


def load_user_list():
    global Users
    with open(user_list_path, 'rb') as file:
        Users = pickle.load(file)
    print(Users)


@atexit.register
def save_user_list():
    global Users
    with open(user_list_path, 'wb') as file:
        pickle.dump(Users, file)


if __name__ == '__main__':
    load_user_list()
    srv = Server()
    srv.init()
    srv.start()
    handle = handle_connections()
    handle.start()
