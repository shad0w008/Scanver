#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core.util import CoroutinePool
from lib import requests
import json
import re
import hashlib

class CmsFind(object):
    def __init__(self,path, justone = False):
        with open(path,'r',encoding='utf8') as f:
            self.cmsdict = json.loads(f.read())
        self.ISSTART = True
        self.result = set()
        self.justone = justone

    def load(self,url,threads=100):
        self.url = url
        pool = CoroutinePool(self.threads)
        for cms in self.cmsdict:
            pool.spawn(self.getver,cms['url'],cms['re'],cms['name'],cms['md5'])
        pool.join()
        return self.result

    def getver(self,path,rep,name,hash):
        if self.ISSTART:
          try:
            req = requests.get(self.url + path)
            if req.status_code==200:
                if re.search(rep,req.text,re.I) or hashlib.md5(req.content).hexdigest()==hash:
                    self.result.add(str(name))
                    if self.justone:
                        self.ISSTART = False
          except:pass


class AppFind(object):
    def __init__(self,path, justone = False):
        #path = https://raw.githubusercontent.com/AliasIO/Wappalyzer/master/src/apps.json
        with open(path,'r',encoding='utf8') as f:
            self.appdict = json.loads(f.read())

    def find(self,res):
        result = set()
        for app,item in self.appdict.items():
            headers = item.get('headers',{})
            htmls = item.get('html',"")
            htmls = htmls if isinstance(htmls,list) else [htmls]
            implies = item.get('implies',"")
            implies = implies if isinstance(implies,list) else [implies]

            for h,r in headers.items():
                for k,v in res.headers.items():
                    if h==k and re.search(r,v):
                        result.add(app)
                        for m in implies:
                            if m:result.add(m)

            for html in htmls:
                if html and re.search(html,res.text):
                    result.add(app)
                    for m in implies:
                        if m:result.add(m)

        return result



if __name__ == '__main__':
    import requests
    res = requests.get('https://www.wappalyzer.com/')
    a=AppFind('./../data/apps.json')
    print(a.find(res))