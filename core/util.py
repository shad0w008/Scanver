#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import ipaddress
import socket
import urllib
import re
import urllib.parse as urlparse
from concurrent.futures import ThreadPoolExecutor

class CoroutinePool(object):
    def __init__(self,threads=10):
        self.pool = ThreadPoolExecutor(max_workers=threads)
    def spawn(self,func,*args,**kwargs):
        self.pool.submit(func,*args,**kwargs)
    def join(self):
        self.pool.shutdown()

def runcmd(cmd, ws=None):
    '''运行命令的通用库'''
    import subprocess
    import codecs
    import locale
    ps = subprocess.Popen(cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=False)
    ret = []
    while True:
        data = ps.stdout.readline()
        if data == '' or ps.poll() is not None:
            break
        else:
            ret.append(data.decode(codecs.lookup(locale.getpreferredencoding()).name))
    return rets

def gethostbyname(name):
    '''域名查ip'''
    try:
        return socket.gethostbyname(name)
    except socket.gaierror:
        return ''

def getdomain(url):
    return urlparse.urlsplit(url).netloc.split(':')[0]

def gethosts(hosts):
    result = []
    hosts = hosts.replace(' ', '')
    if re.search('[a-z]',hosts,re.I):
        hosts = hosts if '://' in hosts else 'http://%s'%hosts
        h = gethostbyname(getdomain(hosts))
        if h:result.append(h)
    else:
        if '/' in hosts:
            result = [str(i) for i in list(ipaddress.IPv4Network(hosts,False).hosts())]
        elif '-' in hosts:
            ret = []
            hosts = hosts.split('-')
            h = hosts[0].split('.')
            for i in range(int(h[3]),int(hosts[1])+1):
                h[3] = str(i)
                ret.append('.'.join(h))
            result = ret
        else:
            result = [hosts] if hosts else []
    return result

def getports(ports):
    ret = []
    for port in ports.split(','):
        port = port.replace(' ', '')
        if '-' in port:
            p = port.split('-')
            ret += [i for i in range(int(p[0]),int(p[1]))]
        else:
            if port:
                ret.append(int(port))
    return ret

def getfiles(path):
    try:
        with open(path,'r') as f:
            for l in f.readlines():
                yield l.strip()
    except:
        pass

def decode_response_text(text):
    for _ in ['UTF-8', 'GB2312', 'GBK', 'iso-8859-1', 'big5']:
        try:
            result = text.encode(_)
            return result
        except Exception as e:
            pass
    # if cannot encode the title . return it.
    return text

if __name__ == '__main__':
    print(gethosts('http://59.41.129.37/'))

