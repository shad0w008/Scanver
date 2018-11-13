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

class RedisNoAuth(BaseHostPlugin):
    bugname = "Redis 未授权访问"
    bugrank = '高危'
    bugdesc = ("""redis 默认不需要密码即可访问，黑客直接访问即可获取数据库中所有信息，造成严重的信息泄露。""")
    bugplan = ("""解决方案"""
               """配置bind选项, 限定可以连接Redis服务器的IP, 并修改redis的默认端口6379."""
               """配置AUTH, 设置密码, 密码会以明文方式保存在redis配置文件中."""
               """配置rename-command CONFIG "RENAME_CONFIG", 这样即使存在 未授权访问, 也能够给攻击者使用config指令加大难度"""
               """好消息是Redis作者表示将会开发”real user”，区分普通用户和admin权限，"""
               """普通用户将会被禁止运行某些命令，如config""")

    BRUTE = True 
    def filter(self,host):
        return host.port == 6379 or host.service == 'redis'

    def verify(self,host,user='',pwd='foobared',timeout=10):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host.host,int(host.port)))
            s.send("INFO\r\n".encode())
            result = s.recv(1024)
            if b'redis_version' in result:
                self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                self.bugreq = "username:%s,password:%s" % (user,pwd)
                self.bugres = str(result)
                return True
            elif b"Authentication" in result:
                s.send(("AUTH %s\r\n"%(pwd)).encode())
                result = s.recv(1024)
                if b'+OK' in result:
                    self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                    self.bugreq = "username:%s,password:%s" % (user,pwd)
                    self.bugres = str(result)
                    return True
        except Exception as e:
            print(e)
        finally:
            s.close()

            