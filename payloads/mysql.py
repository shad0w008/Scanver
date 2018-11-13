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

class MysqlNoAuth(BaseHostPlugin):
    bugname = "Mysql弱口令"
    bugrank = "高危"

    def filter(self,host):
        return host.port == 3306 or host.service == 'mysql'

    @brute
    def verify(self,host,user='root',pwd='root',timeout=10):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host.host,int(host.port)))
            packet = sock.recv(254)
            plugin,scramble = self.get_scramble(packet)
            if not scramble:
                return False
            auth_data = self.get_auth_data(user,pwd,scramble,plugin)
            sock.send(auth_data)
            result = sock.recv(1024)
            if result == b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00":
                self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                self.bugreq = "username:%s,password:%s" % (user,pwd)
                self.bugres = result
                return True
        except Exception as e:
            print(e)
        finally:
            sock.close()

    def get_hash(self,password, scramble):
        hash_stage1 = hashlib.sha1(password.encode()).digest()
        hash_stage2 = hashlib.sha1(hash_stage1).digest()
        to = hashlib.sha1(scramble+hash_stage2).digest()
        reply = [h1 ^ h3 for (h1, h3) in zip(hash_stage1, to)]
        hash = struct.pack('20B', *reply)
        return hash

    def get_scramble(self,packet):
        scramble,plugin = '',''
        try:
            tmp = packet[15:]
            m = re.findall(b"\x00?([\x01-\x7F]{7,})\x00", tmp)
            if len(m)>3:del m[0]
            scramble = m[0] + m[1]
        except:
            return '',''
        try:
            plugin = m[2]
        except:
            pass
        return plugin,scramble

    def get_auth_data(self,user,password,scramble,plugin):
        user_hex = binascii.b2a_hex(user.encode())
        pass_hex = binascii.b2a_hex(self.get_hash(password,scramble))
        data = "85a23f0000000040080000000000000000000000000000000000000000000000" \
             + user_hex.decode() + "0014" + pass_hex.decode()
        if plugin:
            data += binascii.b2a_hex(plugin).decode() \
                 + "0055035f6f73076f737831302e380c5f" \
                 + "636c69656e745f6e616d65086c69626d" \
                 + "7973716c045f7069640539323330360f" \
                 + "5f636c69656e745f76657273696f6e06" \
                 + "352e362e3231095f706c6174666f726d" \
                 + "067838365f3634"
        len_hex = hex(int(len(data)/2)).replace("0x","")
        auth_data = len_hex + "000001" +data
        return binascii.a2b_hex(auth_data)
