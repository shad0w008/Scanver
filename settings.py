#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import os
import sys
sys.path.append('./lib')
import configparser

DEBUG = True
CONFNAME = 'conf.ini'

#获取脚本文件的当前路径
def cur_file_dir():
    path = sys.path[0]
    #判断为脚本文件还是编译后的文件，如果是脚本文件，则返回的是脚本的目录，
    if os.path.isdir(path):
        return path
    elif os.path.isfile(path):
        return os.path.dirname(path)

config = configparser.ConfigParser()
SELFPATH = cur_file_dir()
print(SELFPATH)
config.read(os.path.join(SELFPATH,CONFNAME))
###
DATAPATH = os.path.join(SELFPATH,config.get('data','datapath'))
LOGSPATH = os.path.join(SELFPATH,config.get('data','logspath'))
UPLOADPATH = os.path.join(SELFPATH,config.get('data','uploadpath'))
REPORTPATH = os.path.join(SELFPATH,config.get('data','reportpath'))

#数据库配置
DATABASE = {
    'datatype':config.get('db','datatype'), #'sqlite',#mysql sqlite
    'datahost':config.get('db','datahost'), #'127.0.0.1',
    'dataport':config.getint('db','dataport'), #3306,
    'dataname':config.get('db','dataname'), #'topsecvm',
    'username':config.get('db','username'), #'root',
    'password':config.get('db','password'), #'sa',
    'datapath':config.get('db','datapath'), #'./data/userdata.db'
    'charset' :'utf8mb4',
}
#web网站配置
SETTINGS = {
    "debug"         : DEBUG,
    "gzip"          : True,
    "autoescape"    : True,
    "xsrf_cookies"  : False,
    "login_url"     : "/#/login",
    "cookie_secret" : "e1tuaV1UW3NpXU9bMDFdUFtnZV1TW2RhXUVbc2FdQ1tiaV19",
    "template_path" : os.path.join(os.path.dirname(os.path.realpath(__file__)), config.get('web','template_path')),
    "static_path"   : os.path.join(os.path.dirname(os.path.realpath(__file__)), config.get('web','static_path')),#"./dist"),
}

FILETYPELIST = tuple(config.get('scan','filetype').split('|'))

REDIS = {
    'host':config.get('redis','rhost'),
    'port':config.get('redis','rport'),
    'auth':config.get('redis','rauth'),
}

CLIENTID = config.get('node','nodeid')

if __name__ == '__main__':
   print(tuple(config.get('scan','filetype').split('|')))