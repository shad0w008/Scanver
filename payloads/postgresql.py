#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseHostPlugin

import re
import socket
import binascii
import hashlib
import struct
import re
import time


class PostgresqlNoAuth(BaseHostPlugin):
    bugname = "Postgresql弱口令"
    bugrank = "高危"

    BRUTE = True
    def filter(self,host):
        return host.port == 5432 or host.service == 'postgresql'

    def verify(self,host,user='postgres',pwd='',timeout=10):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host.host,int(host.port)))
            packet_length = len(user) + 7 +len("\x03user  database postgres application_name psql client_encoding UTF8  ")
            p = "%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c"%( 0,0,0,packet_length,0,0,0,0,user,0,0,0,0,0,0,0,0)
            sock.send(p.encode())
            packet = sock.recv(1024)
            salt=b''
            if packet[0] == 82:
                authentication_type = packet[:8]
                c = authentication_type[4:6].hex()
                if c == 5:
                    salt = packet[9:]
                lmd5 = self.make_response(user.encode(),pwd.encode(),salt)
                packet_length1 = len(lmd5) + 5 + len('p')
                pp = 'p%c%c%c%c%s%c'%(0,0,0,packet_length1 - 1,lmd5,0)
                sock.send(pp.encode())
                packet1 = sock.recv(1024)
                if packet1[0] == 82:
                    self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                    self.bugreq = "username:%s,password:%s" % (user,pwd)
                    self.bugres = packet1
                    return True
        except Exception as e:
            print(e)
        finally:
            sock.close()

    def make_response(self,username,password,salt):
        pu = hashlib.md5(password+username).digest()
        buf = hashlib.md5(pu+salt).hexdigest()
        return 'md5' + buf