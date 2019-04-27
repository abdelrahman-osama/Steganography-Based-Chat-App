#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import numpy as np
import pickle


class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        print('listening on port:', self.receive.getsockname()[1])
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    # m = s.decode('utf-8')
                    data_string = Msg()
                    data_string = pickle.loads(s)
                    if s != '':
                        chunk = data_string.msg
                        print(str('')+':'+chunk)
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Msg:
    name = ''
    port = 0
    pub_key = ''
    type = ''
    msg = ''
    users = []

    # stag = np.empty()


class User:
    name = ''
    port = 0
    pub_key = ''


class Client(threading.Thread):
    def connect(self, host, port, name):
        self.sock.connect((host, port))
        msg = Msg()
        msg.name = name
        msg.port = self.sock.getsockname()[1]
        msg.type = 'REG'
        data_string = pickle.dumps(msg)
        self.sock.send(data_string)
        # print("sent")

    def client(self, host, port, msg):
        self.sock.send(pickle.dumps(msg))
        # print "Sent\n"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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

        print("Connecting\n")
        s = ''
        self.connect(host, port, name)
        print("Connected\n")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.start()
        while 1:
            # print "Waiting for message\n"
            msg = Msg()
            msg.msg = input('>>')
            if msg.msg == 'exit':
                break
            if msg.msg == '':
                continue
            print("Sending\n")
            self.client(host, port, msg)
        return(1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
