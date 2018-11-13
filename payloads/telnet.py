#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseHostPlugin

import telnetlib
import re
import socket

class TelnetNoAuth(BaseHostPlugin):
    bugname = "Telnet 未授权访问"
    bugrank = "高危"

    BRUTE = True 
    def filter(self,host):
        return host.port == 23 or host.service == 'telnet'

    def verify(self,host,user='admin',pwd='',timeout=10):
        socket.setdefaulttimeout(timeout)
        try:
            tn = telnetlib.Telnet(host.host,host.port,10)
            #tn.set_debuglevel(3)
            op = tn.read_some()
        except Exception as e:
            print(e)
            return False
        user_match = "(?i)(login|user|username)"
        pass_match = '(?i)(password|pass)'
        login_match = '#|\$|>'
        if re.search(user_match,op):
            try:
                tn.write(str(user)+'\r\n')
                tn.read_until(pass_match,timeout=timeout)
                tn.write(str(pwd)+'\r\n')
                login_info=tn.read_until(login_match,timeout=timeout)
                tn.close()
                if re.search(login_match,login_info):
                    self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                    return True
            except Exception as e:
                pass
        else:
            try:
                info = tn.read_until(user_match,timeout=timeout)
            except Exception as e:
                return False
            if re.search(user_match,info):
                try:
                    tn.write(str(pwd)+'\r\n')
                    tn.read_until(pass_match,timeout=5)
                    tn.write(str(pwd)+'\r\n')
                    login_info = tn.read_until(login_match,timeout=5)
                    tn.close()
                    if re.search(login_match,login_info):
                        self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                        return True
                except Exception as e:
                    return False
            elif re.search(pass_match,info):
                tn.read_until(pass_match,timeout=5)
                tn.write(str(pwd)+'\r\n')
                login_info=tn.read_until(login_match,timeout=5)
                tn.close()
                if re.search(login_match,login_info):
                    self.bugaddr = "%s:%s@%s:%s"%(user,pwd,host.host,host.port)
                    return True

