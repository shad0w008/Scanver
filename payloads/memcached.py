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


class MemcachedNoAuth(BaseHostPlugin):
    bugname = "memcache未授权访问"
    bugrank = '高危'

    BRUTE = True
    def filter(self,host):
        return host.port == 11211 or host.service == 'memcached'

    def verify(self,host,user='',pwd='',timeout=10):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host.host,int(host.port)))
            s.send("stats\r\n".encode())
            result = s.recv(1024)
            if b"version" in result:
                self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                self.bugreq = "username:%s,password:%s" % (user,pwd)
                self.bugres = result
                return True
        except Exception as e:
            print(e)
        finally:
            s.close()