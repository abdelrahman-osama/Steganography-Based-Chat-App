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
from Crypto.PublicKey import RSA
import Crypto.Util.number as CUN
import os

SOCKET_LIST = []
SENDING_LIST = []
TO_BE_SENT = []
SENT_BY = {}
UsersList = []
ServerPort = 0


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

    def getSock(self):
        return self.sock

    def initialise(self, receive):
        self.receive = receive

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        port = random.randint(51400, 51500)
        hostname = '127.0.0.1'
        self.sock.bind((hostname, port))
        print("Server started on port ", port)
        global ServerPort
        ServerPort = port
        # self.sock.listen(1)
        self.sock.listen(2)
        SOCKET_LIST.append(self.sock)
        # print("User APPENDED", SOCKET_LIST[-1])

    def decode(self, img):
        steg_out = LSBSteg(img)
        raw = steg_out.decode_text()
        return raw

    def authenticate(self, msg):
        for user in UsersList:
            if(user.name == msg.name):
                pub_key = user.pub_key
                return pub_key.verify(msg.msg, msg.sig)
        return False

    def run(self):
        while 1:
            read, write, err = select.select(SOCKET_LIST, [], [], 0)
            for sock in read:
                if sock == self.sock:
                    sockfd, addr = self.sock.accept()
                    # print(str(addr), "NEW CONNECTION")
                    SOCKET_LIST.append(sockfd)
                    # print(SOCKET_LIST[len(SOCKET_LIST)-1])
                else:
                    try:
                        s = sock.recv(4096)
                        # total = len(s)
                        # print('MSG TOTAL SIZE = ', total)
                        # m = ''
                        # while(s):
                        #     print('receiving..')
                        #     m += s
                        # if(len(m) == total):
                        #     break
                        data_string = pickle.loads(s)
                        print(data_string, '111111')
                        data_string = private_key.decrypt(data_string)
                        print(data_string, '2222222')
                        decrypted_msg = pickle.loads(data_string)
                        #
                        #
                        print(decrypted_msg, '333333')

                        # # print(data_string.type, 'MESSAGE TYPE')
                        # decrypted_msg =  decrypted_msg
                        if(data_string.type == 'BYE'):
                            # print(str(sock.getpeername()), "hena??")
                            SOCKET_LIST.remove(sock)
                            print("User left the chat")
                            sock.close()
                        # if  == '':
                        #     SOCKET_LIST.remove(sock)
                        #     print("User left the chat")
                        #     sock.close()
                        else:
                            # if data_string.type == 'AMSG':
                                # TO_BE_SENT.append(s)

                            is_authenticated = self.authenticate(data_string)
                            if(is_authenticated):
                                out = self.decode(decrypted_msg.msg)
                            # out =
                            # out = data_string.msg
                                print(data_string.name, ': ', out)
                            else:
                                print('Failed to authenticate.')
                            # SENT_BY[s] = (str(sock.getpeername()))
                    except:
                        traceback.print_exc(file=sys.stdout)
                        SOCKET_LIST.remove(sock)
                        print("REMOVED", sock)
                        sock.close()


class Msg:
    name = ''
    port = 0
    pub_key = ''
    receiver_name = ''
    receiver_port = 0
    type = ''
    sig = 0
    msg = ''
    users = []
    sock = ''

    # stag = np.empty()


class User:
    name = ''
    port = 0
    pub_key = ''

    def __str__(self):
        out = 'Name : '
        out += self.name
        out += ' Port :'
        out += str(self.port)
        out += ' PUB_KEY : '
        out += str(self.pub_key.exportKey('PEM'))
        return out


class MainServerConnection(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        print('listening from main server on port:',
              self.receive.getsockname()[1])
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    # m = s.decode('utf-8')
                    data_string = Msg()
                    data_string = pickle.loads(s)
                    print(data_string.type, 'MSG TYPE')
                    if(data_string.type == 'ULST'):
                        global UsersList
                        UsersList = data_string.users
                        print("USER LIST UPDATED")
                        for i in UsersList:
                            print(str(i))
                    # if s != '':
                    #     chunk = data_string.msg
                    #     print(str('')+':'+chunk)
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):

    def encrypt(self, msg):
        steg = LSBSteg(cv2.imread("guc1.png"))
        res = steg.encode_text(msg)
        return res


    def connect(self, host, port, name, pub_key):
        self.sock.connect((host, port))
        msg = Msg()
        msg.name = name
        msg.port = ServerPort
        msg.pub_key = pub_key
        msg.type = 'REG'
        # msg.sock = self.sock
        data_string = pickle.dumps(msg)
        self.sock.send(data_string)
        # print("sent")

    def client(self, host, port, msg, srv):
        if msg.type == 'AMSG':
            self.sock.send(pickle.dumps(msg))
        # self.sock.send(pickle.dumps(msg))
        # print "Sent\n"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        global private_key
        private_key = RSA.generate(2048)
        pub_key =  private_key.publickey()

        try:
            # host = input("Enter the hostname\n>>")
            # port = int(input("Enter the port\n>>"))
            host = '127.0.0.1'
            port = 5535
            name = input("Enter your name: ")
            # user.port

        except EOFError:
            print("Error")
            return 1

        #

        # time.sleep(1)
        srv = Server()
        srv.daemon = True
        print("Starting service")
        srv.init()
        time.sleep(1)
        print("Connecting\n")
        s = ''
        # servSock = srv.getSock()
        self.connect(host, port, name, pub_key)
        print("Connected\n")
        time.sleep(1)
        srv.start()
        time.sleep(1)
        print("Starting handler")
        handle = handle_connections()
        handle.start()
        time.sleep(1)
        receive = self.sock
        srv2 = MainServerConnection()
        srv2.initialise(receive)
        srv2.daemon = True
        print("Starting service")
        srv2.start()
        while 1:
            # print "Waiting for message\n"

            try:
                msg = Msg()
                uinput = input('>>')
                uinput = uinput.split(':')
                msg.type = uinput[0].strip()
                if(msg.type == 'DMSG'):
                    msg.receiver_name = uinput[1].strip()
                    msg.msg = self.encrypt(uinput[2].strip())
                    # msg.receiver_port = 0
                # msg.msg = uinput[1]
                else:
                    msg.msg = self.encrypt(uinput[1].strip())

                K = CUN.getRandomNumber(128, os.urandom)
                signature = private_key.sign(bytes(msg.msg), K)
                msg.sig = signature
                msg.name = name.strip()
            except:

                traceback.print_exc(file=sys.stdout)
                continue
            if(msg.type == 'AMSG'):
                TO_BE_SENT.append(msg)
                SENT_BY[msg] = (msg.name)
            elif(msg.type == 'DMSG'):
                TO_BE_SENT.append(msg)
                SENT_BY[msg] = (msg.name)
            elif(msg.type == 'FTCH'):
                self.sock.send(msg)
            elif msg.msg == 'exit':
                break
            elif msg.msg == '':
                continue
            print("Sending\n")
            # self.client(host, port, msg, srv)
        return(1)


class handle_connections(threading.Thread):
    def run(self):
        while 1:
            for items in TO_BE_SENT:
                msg = items
                if(msg.type == 'AMSG'):
                    for user in UsersList:
                        try:
                            self.sock = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM)
                            self.sock.connect(('127.0.0.1', user.port))
                            # msg = pickle.loads(items)
                            # if(msg.type == 'AMSG'):
                            K = CUN.getRandomNumber(128, os.urandom)
                            enc_items = user.pub_key.encrypt(bytes(items.msg), K)[0]
                            try:
                                self.sock.send(pickle.dumps(enc_items))
                                # time.sleep(1)
                            finally:
                                self.sock.close()
                            # self.sock.shutdown()
                        except:
                            traceback.print_exc(file=sys.stdout)
                    TO_BE_SENT.remove(items)
                    del(SENT_BY[items])
                if(msg.type == 'DMSG'):
                    port = 0
                    pub_key = ''
                    for user in UsersList:
                        if(user.name == msg.receiver_name):
                            port = user.port
                            pub_key = user.pub_key
                    try:
                        self.sock = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)
                        self.sock.connect(('127.0.0.1', port))
                        K = CUN.getRandomNumber(128, os.urandom)
                        enc_items = pub_key.encrypt(items, K)[0]
                        try:
                            self.sock.send(pickle.dumps(enc_items))
                        finally:
                            self.sock.close()
                    except:
                        traceback.print_exc(file=sys.stdout)
                    TO_BE_SENT.remove(items)
                    del(SENT_BY[items])


if __name__ == '__main__':

    # time.sleep(1)
    print("Starting client")
    cli = Client()
    cli.start()
