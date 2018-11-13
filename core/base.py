#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from lib import requests
import re
import socket
import urllib.parse as urlparse
import settings
from core.cmsfind import CmsFind
CMS = CmsFind(settings.DATAPATH + '/cmsdata.json')

####################################
class BaseWebSite(object):
    '''定义一个网站的基类'''
    error_flag = re.compile(r'Error|Error Page|Unauthorized|Welcome to tengine!|Welcome to OpenResty!|invalid service url|Not Found|不存在|未找到|410 Gone|looks like something went wrong|Bad Request|Welcome to nginx!', re.I)
    def __init__(self,url,proxy={},timeout=10,load=True):
        self.proxy = proxy
        self.timeout = timeout
        if url and url.startswith('//'):
            url = 'http:'+url
        if url and not url.upper().startswith('HTTP'):
            url = 'http://%s'%url
        self.url        = url
        parser          = urlparse.urlsplit(self.url)
        self.scheme     = parser.scheme #https
        self.netloc     = parser.netloc #www.baidu.com
        self.path       = parser.path   #www.baidu.com
        self.domain     = ''
        if re.search('a-z',self.netloc,re.I):
            self.domain = self.netloc.split(':')[0]
        self.host = self.gethostbyname(self.netloc.split(':')[0])
        try:
            self.port = self.netloc.split(':')[1]
        except:
            self.port = 443 if self.scheme.upper() == 'HTTPS' else 80
        self.status_code= 0
        self._content   = set() #struts2 dedecms ...
        self.headers    = {}
        self.server     = '|' #Server: nginx/1.8.0 #Apache Tomcat/7.0.59
        self.xpoweredby = '|' #X-Powered-By: PHP/5.6.31'
        self.title      = ''
        self.cmsver     = ''

        if load:
            try:
                self.pag404 = self.getpag404()
                self.load()
            except:
                pass

    def getpag404(self):
        try:
            url = self.url + "/pag404notfindtestscanol.%s"%self.host
            return requests.get(
                url,
                allow_redirects=True,
                #proxies=self.proxy,
                #timeout=self.timeout,
                verify=False)
        except:pass

    def load(self):
        res = requests.get(
                self.url,
                allow_redirects=False,
                #proxies=self.proxy,
                #timeout=self.timeout,
                verify=False)
        self.headers = res.headers
        self.server = res.headers.get('Server',self.server)
        xpoweredby1 = res.headers.get('X-Powered-By','')
        xpoweredby2 = self.findxpoweredby(res)
        self.xpoweredby = xpoweredby2+'|'+self.xpoweredby if xpoweredby2 else xpoweredby1
        res = requests.get(
                self.url,
                #proxies=self.proxy,
                #timeout=self.timeout,
                verify=False)
        self.status_code = res.status_code
        self.title = ''.join(
                    re.findall(r"<title>([\s\S]*?)</title>",
                    res.text.encode(res.encoding).decode('utf-8'),
                    re.I))
        self.server = res.headers.get('Server',self.server)
        xpoweredby3 = res.headers.get('X-Powered-By',self.xpoweredby)
        xpoweredby4 = self.findxpoweredby(res)
        self.xpoweredby = xpoweredby4 + '|' + self.xpoweredby if xpoweredby4 else xpoweredby3+'|'+self.xpoweredby

        if 'JSP' in self.xpoweredby:
            server = self.javaserver(self.scheme,self.netloc)
            self.server = server + '|' + self.server if server else res.headers.get('Server')

        self.cmsver = '|'.join(list(CMS.load(self.url)))

    @staticmethod
    def findxpoweredby(res):
        xpoweredby = ' '
        headers = str(res.headers)
        content = res.text
        if 'ASP.NET' in headers or 'ASPSESSIONID' in headers:
            xpoweredby += '|ASP'
        if 'PHPSESSIONID' in headers:
            xpoweredby += '|PHP'
        if 'JSESSIONID' in headers:
            xpoweredby += '|JSP'
        if re.search(r'name="__VIEWSTATE" id="__VIEWSTATE"',content):
            xpoweredby += '|ASP'
        """
        if re.search(r'''href[\s]*=[\s]*['"][./a-z0-9]*\.jsp[x'"]''',content,re.I):
            xpoweredby += 'JSP'
        if re.search(r'''href[\s]*=[\s]*['"][./a-z0-9]*\.action['"]''',content,re.I):
            xpoweredby += 'JSP'
        if re.search(r'''href[\s]*=[\s]*['"][./a-z0-9]*\.do['"]''',content,re.I):
            xpoweredby += 'JSP'
        if re.search(r'''href[\s]*=[\s]*['"][./a-z0-9]*\.asp[x'"]''',content,re.I):
           xpoweredby += 'ASP'
        if re.search(r'''href[\s]*=[\s]*['"][./a-z0-9]*\.php[\?'"]''',content,re.I):
           xpoweredby += 'PHP'
        """
        return xpoweredby

    @staticmethod
    def gethostbyname(name):
        '''域名查ip'''
        try:
            return socket.gethostbyname(name)
        except socket.gaierror:
            return name

    @staticmethod
    def javaserver(scheme,netloc):
        server = ' '
        try:
            res = self.pag404
            tomcat = ''.join(re.findall("<h3>(.*?)</h3>",res.text))
            weblogic = ''.join(re.findall("<H4>(.*?)404 Not Found</H4>",res.text))
            if res.status_code == 404:
                if 'Tomcat' in res.text:
                    server = tomcat
                if 'Hypertext' in res.text:
                    server = 'Weblogic '+weblogic
        except:pass
        return server

    @property
    def content(self):
        for s in self.server.split('|') + self.xpoweredby.split('|'):
            if s:self._content.add(s.strip())
        if self.cmsver:
            self._content.add(self.cmsver.strip())
        return '|'.join(self._content).lower()

    @content.setter
    def content(self,value):
        self._content.add(value)

class BaseHost(object):
    '''主机'''
    def __init__(self,host,port,service=None):
        self.host = host
        self.port = int(port)
        self.service = service

class ConnectionError(requests.ConnectionError):
    pass


if __name__ == '__main__':
    u=[
        'http://127.0.0.1/www',
    ]
    for i in u:
        s = BaseWebSite(i)
        print(s.server,s.xpoweredby)