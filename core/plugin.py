#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

import os
import sys
import glob
import time
import re
import datetime
from imp import find_module,load_module,acquire_lock,release_lock
from abc import ABC, ABCMeta, abstractmethod

from core.log import logging

class PluginsManage(type):
    __not_import = ['__init__.py']
    __pluginpath = './'
    __plugins = {}

    @classmethod
    def load(cls,path=None,not_import=[],newtable=True):
        path = path or cls.__pluginpath
        not_import = not_import or cls.__not_import
        plugins = [p.split(os.sep)[-1] for p in glob.glob(path+'/'+'*.py')]
        for plugin in plugins:
            if plugin not in not_import:
                fn = None
                plug_name = '.'.join(plugin.split('.')[:-1])
                try:
                    acquire_lock()
                    fn, filename, desc = find_module(plug_name, [path])
                    load_module(plug_name, fn, filename, desc)
                except Exception as e:
                    logging.error(u"Plugin:%s Error:%s"%(plugin,e))
                finally:
                    if fn:fn.close()
                    release_lock()

    @property
    def plugins(self):
        return self.get_plugins()

    def __init__(self,name,bases,dict):
        if hasattr(self,'plugins'):
            self.reg_plugin(self)
        else:
            self.__plugins = {}

    def reg_plugin(self,plugin):
        #plug_name = '.'.join([plugin.__module__,plugin.__name__])
        #print('load plugin %s.%s'%(plugin.__module__,plugin.__name__))
        self.__plugins[plugin.__name__] = plugin()

    def unreg_plugin(self,plug_name):
        if plug_name in self.__plugins:
            del self.__plugins[plug_name]

    @classmethod
    def get_plugins(self,plug_name=None):
        if plug_name:
            return [self.__plugins.get(plug_name,None)]
        return self.__plugins.values()

class BasePlugin(object):
    #def __init__(self):
    #下面三个必须要有
    bugname    = '',  #漏洞名称      （必须
    bugrank    = '',  #漏洞等级      （必须，分四个等级【紧急，高危，中危，低危】 如果不是这个名称要进行相应转换
    bugaddr    = '',  #漏洞地址      （必须，可以是url地址或者某个IP地址对应端口如 http://127.0.0.1/bugaddr?id=1或 127.0.0.1:1433
    #下面这几个可有可无
    bugreq     = '',  #原始请求包    （没有填空，
    bugres     = '',  #原始返回结果  （没有填空，
    bugtag     = '',  #漏洞标签      （没有填空，以|分隔，如 SQL|XSS|弱口令
    bugnote    = '',  #漏洞备注，比如对应的漏洞链接啥的
    bugowasp   = '',  #owasp对应关系 （没有填空
    bugplan    = '',  #修复方案      （没有填空，
    bugdesc    = '',  #漏洞详情      （没有填空，
    bugnumber  = '',  #漏洞编号      （没有填空，以|分隔，如 CVE-2017-12345|CNVD-2017-12345|CWE-17


    BRUTE = False #是否要进行用户名密码爆破尝试

    @classmethod
    def payloads(self):
        return [p for p in self.plugins if isinstance(p,self)]

class BaseHostPlugin(BasePlugin,metaclass=PluginsManage):
    '''
    针对主机应用的插件，如redis未授权访问、memcache未授权访问等
    插件对每个IP对应端口只扫描一次
    '''

    @abstractmethod
    def filter(self,host):
        pass

    @abstractmethod
    def verify(self,host,user='',pwd='',timeout=10):
        pass

    @abstractmethod
    def exploit(self,host,cmd='whoami'):
        pass

class BaseWebPlugin(BasePlugin,metaclass=PluginsManage):
    '''
    针对web应用的插件，如phpcms远程命令执行、tomcat弱口令等
    插件对每个网站只扫描一次
    '''
    @abstractmethod
    def filter(self,web):
        pass

    @abstractmethod
    def verify(self,web,user='',pwd='',timeout=10):
        pass

    @abstractmethod
    def exploit(self,web,cmd='whoami'):
        pass

class BaseHttpPlugin(BasePlugin,metaclass=PluginsManage):
    '''
    针对url的，如sql注入，xss等
    插件对每个url扫描一次
    用法： 插件继承该类即可
        class PlugDemo(BaseWebPlugin):
            def filter(self,web):
                pass

            def verify(self,web,user='',pwd='',timeout=10):
                pass

    '''

    @abstractmethod
    def filter(self,web,req,res):
        pass

    @abstractmethod
    def verify(self,web,req,res):
        pass

    @abstractmethod
    def exploit(self,web,req,res,cmd='whoami'):
        pass

def brute(f):
    '''用法： 在插件的verify函数上 使用装饰器
        class PlugDemo(BaseWebPlugin):
            def filter(self,web):
                pass

            @brute
            def verify(self,web,user='',pwd='',timeout=10):
                pass
    '''
    def F(self,*args,**kwargs):
        self.BRUTE = True
        return f(self,*args,**kwargs)
    return F


if __name__ == "__main__":
    PluginsManage.load('./payloads')
    for plug in BasePlugin.payloads():
        print(plug)