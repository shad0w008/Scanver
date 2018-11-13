#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092

import sys
import time
from lib.libnmap.process import NmapProcess
from lib.libnmap.parser import NmapParser, NmapParserException
from core.util import getports
from core.log import logging


class PortScan(object):
    def __init__(self,target,
                    options = "-sT -Pn -sV -O --script=banner -T5 --min-hostgroup 100 --min-parallelism 100 --host-timeout 10m --script-timeout 5m --defeat-rst-ratelimit",
                    ports = None,
                    neping = None,
                    threads = None,
                    timeout = 10000):
        self.target     = target
        self.options    = options
        self.timeout    = timeout
        if ports:
            self.options + '-p ' + ','.join(getports(ports))

    def scan(self):
        result = {}
        try:
            result = self.parse_report(self.do_scan())
        except NmapParserException as e:
            logging.error("Exception raised while parsing scan: {0}".format(e.msg))

        return result

    def do_scan(self):
        trycnt = 0
        retrycnt = 3
        while True:
            runtime = 0
            if trycnt >= retrycnt:
                return 'retry overflow'
            try:
                nmap_proc = NmapProcess(targets=self.target, options=self.options, safe_mode=False)
                nmap_proc.run_background()
                while nmap_proc.is_running():
                    print("Nmap:{0} ETC: {1} DONE: {2}%".format(self.target,nmap_proc.etc,nmap_proc.progress))
                    if runtime >= self.timeout:	# 运行超时，结束掉任务，休息1分钟, 再重启这个任务
                        nmap_proc.stop()
                        time.sleep(60)
                        trycnt += 1
                        break
                    else:
                        time.sleep(5)
                        runtime += 5
                if nmap_proc.is_successful():
                    return nmap_proc.stdout
            except Exception as e:
                print(e)
                trycnt += 1
                if trycnt >= retrycnt:
                    return e

    @classmethod
    def parse_report(self,nmap_report,states = ['open']):
        result = {}
        nmap_report = NmapParser.parse(nmap_report)
        for host in nmap_report.hosts:
            h = host.address
            result[h]              = {}
            result[h]['ports']     = set()
            result[h]['ostype']    = '|'.join(host.os.osmatch())
            result[h]['hostname']  = '|'.join(host.hostnames)
            result[h]['mac']       = host.mac
            result[h]['status']    = host.status
            for serv in host.services:
                data = serv.scripts_results[0]['output'] if len(serv.scripts_results) else ''
                if serv.state in states:
                    data = serv.scripts_results[0]['output'] if len(serv.scripts_results) else ''
                    result[h]['ports'].add((
                        host.address,
                        serv.port,
                        serv.protocol,
                        serv.state,
                        serv.service,
                        '',
                        '',
                        serv.banner,
                        data))
        return result

if __name__=='__main__':
    s = PortScan('127.0.0.1')
    s.parse_report(open('sasa','r').read())