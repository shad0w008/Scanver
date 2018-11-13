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


class RsyncNoAuth(BaseHostPlugin):
    bugname = "Rsync 未授权访问"
    bugrank = "高危"

    def filter(self,host):
        return host.port == 873 or host.service == 'rsync'

    def verify(self,host,user='',pwd='',timeout=15):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host.host, int(host.port)))
            sock.sendall("\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a".encode())
            ret = sock.recv(256)
            if b"RSYNCD" in ret:
                sock.sendall("\x0a".encode())
            data = sock.recv(256)
            if len(data)>0:
                self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                self.bugreq = "username:%s,password:%s" % (user,pwd)
                #self.bugres = data
                return True
        except Exception as e:
            print(e)
        finally:
            sock.close()


