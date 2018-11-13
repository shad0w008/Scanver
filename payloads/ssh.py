#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from lib import paramiko
import socket
from core.plugin import BaseHostPlugin

class SshNoAuth(BaseHostPlugin):
    bugname = 'SSH 弱口令'
    bugrank = '紧急'

    BRUTE = True
    def filter(self,host):
        return host.port == 22 or host.service == 'ssh'

    def verify(self,host,user='',pwd='',timeout=5):
        socket.setdefaulttimeout(timeout)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=host.host,port=host.port,username=user,password=pwd,timeout=timeout)
            self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
            self.bugreq = "user:%s,pwd:%s" % (user,pwd)
            return True
        except Exception as e:
            print(e)
        finally:
            ssh.close()
