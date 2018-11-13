#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseWebPlugin,BaseHostPlugin,brute

import ftplib
import re
import socket

class FtpWeakPass(BaseHostPlugin):
    bugname = "Ftp 未授权访问"
    bugrank = "高危"

    def filter(self,host):
        return host.port == 21 or host.service == 'ftp'

    @brute
    def verify(self,host,user='anonymous',pwd='',timeout=5):
        socket.setdefaulttimeout(timeout)
        ftp = ftplib.FTP()
        try:
            ftp.connect(host.host,int(host.port))
            ftp.login(user,pwd)
            self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
            return True
        except Exception as e:
            print(e)
        finally:
            ftp.quit()

