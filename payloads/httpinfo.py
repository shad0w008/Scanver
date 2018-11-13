#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import re

from core.plugin import BaseHttpPlugin,BaseWebPlugin,BaseHostPlugin,brute

class CodeReview(BaseHttpPlugin):
    PAYLOADS = re.compile(r"<[%?][ ]*[^x][a-z]*")

    bugname = '源码泄漏'
    bugrank = '中危'

    def filter(self,crawle,req,res):
        ct = res.headers.get('content-type','')
        return "text" in ct

    def verify(self,crawle,req,res):
        r = self.PAYLOADS.findall(res.text)
        if r:
            self.bugaddr = req.url
            self.bugreq = str(req)
            self.bugres = str(r[0])
            return True

class Jqueryvd(BaseHttpPlugin):
    PAYLOADS = re.compile(r'1.\d.\d')

    bugname = 'jquery版本过低'
    bugrank = '低危'

    def filter(self,crawle,req,res):
        return 'jquery' in req.url \
            or 'jquery.org/license' in res.text[:100]

    def verify(self,crawle,req,res):
        '''jquery版本小于1.11则报'''

        r = self.PAYLOADS.findall(res.text[:100])
        if r:
           self.bugaddr = req.url
           self.bugreq = str(r[0])
           return True

class FileUploadPage(BaseHttpPlugin):
    PAYLOADS = re.compile(r'''<input.*?type=["']*file["'].*?>''')

    bugname = '文件上传页面'
    bugrank = '低危'

    def filter(self,crawle,req,res):
        ct = res.headers.get('content-type','')
        return "text" in ct

    def verify(self,crawle,req,res):

        r = self.PAYLOADS.findall(res.text)
        if r :
           self.bugaddr = req.url
           self.bugreq = str(r[0])
           return True

class PathInfoView(BaseHttpPlugin):
    PAYLOADS = (
        re.compile(r"[^a-z0-9]([c-k]:[\\/][\\/.\-_a-z0-9]*)",re.I),
    )

    bugname = '物理路径泄漏'
    bugrank = '低危'

    def filter(self,crawle,req,res):
        ct = res.headers.get('content-type','')
        return "text" in ct and not req.url.endswith('js')

    def verify(self,crawle,req,res):
        for p in self.PAYLOADS:
            r = p.findall(res.text)
            if r :
               self.bugaddr = req.url
               self.bugreq = '\r\n'.join(r)
               return True

class IntranetIPleakage(BaseHttpPlugin):
    PAYLOADS = re.compile(r'((192\.168|172\.([1][6-9]|[2]\d|3[01]))(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}|10(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){3})')

    bugname = '内网IP泄漏'
    bugrank = '低危'

    def filter(self,crawle,req,res):
        return True

    def verify(self,crawle,req,res):
        r = self.PAYLOADS.findall(res.text)
        if r:
           self.bugaddr = req.url
           self.bugreq = '\r\n'.join(r)
           return True

class DirectoryListing(BaseHttpPlugin):
    PAYLOADS = (
        re.compile(r'<title>Index of /',re.I),
        re.compile(r'<a href="?C=N;O=D">Name</a>',re.I),
        re.compile(r'<A HREF="?M=A">Last modified</A>',re.I),
        re.compile(r'Last modified</a>',re.I),
        re.compile(r'Parent Directory</a>',re.I),
        re.compile(r'<TITLE>Folder Listing.',re.I),
        re.compile(r'<table summary="Directory Listing',re.I),
        re.compile(r'">[To Parent Directory]</a><br><br>',re.I),
        re.compile(r'&lt;dir&gt; <A HREF="/',re.I),
        re.compile(r'''<pre><A HREF="/">\[''',re.I),
    )

    bugname = '列目录漏洞'
    bugrank = '中危'

    def filter(self,crawle,req,res):
        ct = res.headers.get('content-type','')
        return ct not in ("octet-stream","image")

    def verify(self,crawle,req,res):
        for p in self.PAYLOADS:
            r = p.findall(res.text)
            if r:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res.text)
                return True

class BackDoor(BaseHttpPlugin):
    PAYLOADS = [
        "->||<-",
        "JspSpy",
        "Georg says, 'All seems fine'",
    ]

    bugname = '后门文件'
    bugrank = '高危'

    def filter(self,crawle,req,res):
        return True

    def verify(self,crawle,req,res):
        for p in self.PAYLOADS:
            if p in res.text:
                self.bugaddr = req.url
                return True

