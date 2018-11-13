from core.plugin import BaseWebPlugin,BaseHostPlugin,brute

import requests
import re

class GitBack(BaseWebPlugin):
    bugname = "备份文件泄漏"
    bugrank = "中危"

    def filter(self,web):
        return True

    def verify(self,web,user='',pwd='',timeout=10):
        pass



