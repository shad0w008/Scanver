#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

from core import scan
from service import app,TaskManage

@TaskManage.task(tasktype='-1')
def handwork():
    '''手工录入'''
    pass

@TaskManage.task(tasktype='-1')
def automatic():
    '''批量导入'''
    pass

@TaskManage.task(tasktype='host')
def portscan(Q):
    '''资产扫描'''
    s = scan.ServiceScan(Q)
    s.start()

@TaskManage.task(tasktype='host')
def hostscan(Q):
    '''主机扫描'''
    s = scan.HostsScan(Q)
    s.start()

@TaskManage.task(tasktype='host')
def pluginscan(Q):
    '''插件扫描'''
    s = scan.PluginsScan(Q)
    s.start()

@TaskManage.task(tasktype='web')
def bugscan(Q):
    '''网站扫描'''
    s = scan.HttpScan(Q)
    s.start()

#@TaskManage.task(tasktype='web')
def domainscan(Q):
    '''域名扫描'''
    s = scan.DomainScan(Q)
    s.start()

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 2:
        cmd = sys.argv[1]
        if cmd == 'init':
            TaskManage.load()
            TaskManage.init()
        elif cmd == 'start':
            TaskManage.loop()
        else:
            app.start()
    else:
        print('''scanol start ...
        cmd: python3 tasks.py init|start|worker <celery argv>
        ''')


