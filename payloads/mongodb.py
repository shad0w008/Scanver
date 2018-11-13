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


class MongodbNoAuth(BaseHostPlugin):
    bugname = "Mongodb 未授权访问"
    bugrank = "高危"

    def filter(self,host):
        return host.port == 27017 or host.service == 'mongodb'

    def verify(self,host,user='',pwd='',timeout=10):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host.host,int(host.port)))
            data = binascii.a2b_hex("3a000000a741000000000000d4070000"
                                    "0000000061646d696e2e24636d640000"
                                    "000000ffffffff130000001069736d61"
                                    "73746572000100000000")
            sock.send(data)
            result = sock.recv(1024)
            if b"ismaster" in result:
                data = binascii.a2b_hex("480000000200000000000000d40700"
                                        "000000000061646d696e2e24636d64"
                                        "000000000001000000210000000267"
                                        "65744c6f6700100000007374617274"
                                        "75705761726e696e67730000")
                sock.send(data)
                result = sock.recv(1024)
                if b"totalLinesWritten" in result:
                    self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                    self.bugreq = "username:%s,password:%s" % (user,pwd)
                    self.bugres = str(result)
                    return True
        except Exception as e:
            print(e)
        finally:
            sock.close()

