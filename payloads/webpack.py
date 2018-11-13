#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import re
import copy
import requests
from core.plugin import BaseHttpPlugin

class CodeReview(BaseHttpPlugin):
    bugname = 'WEBPACK打包源文件泄漏'
    bugrank = '中危'
    bugdesc = "攻击者可通过该文件重建出系统目录结构，打开按F12可看到webpack://目录，在里面可以找到相关的内部目录结果及接口信息"
    bugplan = "建议修改webpack配置为build模式并且按需加载。"

    def filter(self,crawle,req,res):
        return req.path.endswith(('.js','.JS'))

    def verify(self,crawle,req,res):
        req = copy.deepcopy(req)
        req.path = req.path + '.map'
        res = req.response()
        if res.status_code == 200 and 'webpack:///' in res.text:
            self.bugaddr = req.url
            self.bugreq = str(req.headers)
            return True

