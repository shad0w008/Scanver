#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseHttpPlugin,BaseWebPlugin,BaseHostPlugin,brute

import re
import socket
import binascii
import hashlib
import struct
import re
import time

class MssqlNoAuth(BaseHostPlugin):
    bugname = "Mssql弱口令"
    bugrank = "高危"

    def filter(self,host):
        return host.port == 1433 or host.service == 'mssql'

    @brute
    def verify(self,host,user='sa',pwd='',timeout=10):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host.host,int(host.port)))
            hh = binascii.b2a_hex(host.host.encode())
            husername = binascii.b2a_hex(user.encode())
            lusername = len(user)
            lpassword = len(pwd)
            ladd = len(host.host)+len(str(host.port))+1
            hladd = hex(ladd).replace('0x','')
            hpwd = binascii.b2a_hex(pwd.encode())
            pp = binascii.b2a_hex(str(host.port).encode())
            address = hh+'3a'.encode()+pp
            hhost = binascii.b2a_hex(host.host.encode())
            data = ("02000200000000001234567890000000"
                    "00000000000000000000000000000000"
                    "000000000000ZZ544000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000X33600000000000000000"
                    "00000000000000000000000000000000"
                    "000000000Y3739333400000000000000"
                    "00000000000000000000000000000000"
                    "000000040301060a0901000000000200"
                    "0000000070796d7373716c0000000000"
                    "00000000000000000000000000000000"
                    "00000712345678900000000000000000"
                    "00000000000000000000000000000000"
                    "00ZZ3360000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "000Y0402000044422d4c696272617279"
                    "0a00000000000d1175735f656e676c69"
                    "73680000000000000000000000000000"
                    "0201004c000000000000000000000a00"
                    "0000000000000000000000000069736f"
                    "5f310000000000000000000000000000"
                    "00000000000000000000000501353132"
                    "000000030000000000000000").encode()
            data1 = data.replace(data[16:16+len(address)],address)
            data2 = data1.replace(data1[78:78+len(husername)],husername)
            data3 = data2.replace(data2[140:140+len(hpwd)],hpwd)
            if lusername >= 16:
                data4 = data3.replace(b'0X',str(hex(lusername)).replace('0x','').encode())
            else:
                data4 = data3.replace(b'X',str(hex(lusername)).replace('0x','').encode())
            if lpassword >= 16:
                data5 = data4.replace(b'0Y',str(hex(lpassword)).replace('0x','').encode())
            else:
                data5 = data4.replace(b'Y',str(hex(lpassword)).replace('0x','').encode())
            data6 = data5.replace(b'ZZ',str(hex(ladd)).replace('0x', '').encode())
            data7 = binascii.a2b_hex(data6)
            sock.send(data7)
            packet = sock.recv(1024)
            if b'master' in packet:
                self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                self.bugreq = "username:%s,password:%s" % (user,pwd)
                self.bugres = packet
                return True
        except Exception as e:
            print(e)
        finally:
            sock.close()



