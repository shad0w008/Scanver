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


class ZookeeperNoAuth(BaseHostPlugin):
    bugname = "Zookeeper未授权访问"
    bugrank = "高危"

    def filter(self,host):
        return host.port == 2181 or host.service == 'zookeeper'

    def verify(self,host,user='',pwd='',timeout=10):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host.host, host.port))
            s.send("envi".encode())
            data = s.recv(1024)
            if b'Environment' in data:
                self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                self.bugreq = "username:%s,password:%s" % (user,pwd)
                self.bugres = data
                return True
        except Exception as e:
            print(e)
        finally:
            s.close()


