#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092
import os
import sys
import time
import datetime
import queue
import threading
import multiprocessing

from celery import Celery
import settings
import models
from core.log import logging
from core.plugin import PluginsManage,BaseHostPlugin,BaseWebPlugin


NODEID = settings.CLIENTID
app = Celery(NODEID)
app.conf.update(
    CELERY_IMPORTS          = ('tasks'),
    BROKER_URL              = 'redis://:%s@%s:%s/0'%(settings.REDIS['auth'],settings.REDIS['host'],settings.REDIS['port']),
    CELERY_RESULT_BACKEND   = 'redis://:%s@%s:%s/0'%(settings.REDIS['auth'],settings.REDIS['host'],settings.REDIS['port']),
)

class TaskManage(object):
    tasklist = {}
    count = multiprocessing.cpu_count()
    Queue = queue.Queue(count)

    @classmethod
    def task(self,tasktype='-1',*args,**kwargs):
        '''
        任务类型有
        web,    适用于web的任务
        host,   适用于主机扫描的任务
        sched,  定时执行任务 timefor = 定时时间
        loopd,  定时循环任务 timeout = 循环时间
        '''
        def F(f):
            if f.__name__ not in self.tasklist.keys():
                logging.load('Reg-Task: ' + f.__name__ + '\n')
                self.tasklist[f.__name__]               = {}
                self.tasklist[f.__name__]['handler']    = f
                self.tasklist[f.__name__]['name']       = f.__name__
                self.tasklist[f.__name__]['doc']        = f.__doc__
                self.tasklist[f.__name__]['type']       = tasktype
            if tasktype == '-1':
                pass
            elif tasktype == 'sched':
                pass
            elif tasktype == 'loopd':
                pass
            else:
                app.task(f)
            return f
        return F

    @classmethod
    def addtask(self,Q,cel=True):
        name = Q.tasktype.task_name
        taskid = str(Q.task_id)
        if name:# in self.tasklist.keys():
            if cel:
                nodeid      = Q.tasknode.node_id if Q.tasknode else 'tasks' #没有指定任务节点就随机
                task        = app.send_task('%s.%s'%(nodeid,name),args=[taskid])
                Q.task_pid  = task.id
                Q.task_code = task.status
                Q.save()
            else:
                logging.info('Runing-Task:[%s]-[%s]'%(str(Q.tasktype.task_name),str(Q.task_host)))
                self.tasklist[name]['handler'](taskid)

    @classmethod
    def stoptask(self,task_pid):
        '''停止任务'''
        app.control.revoke(task_pid,terminate=True)

    @classmethod
    def load(self):
        '''更新节点信息'''
        MC = models.ClientNode
        RC,cd = MC.get_or_create(node_id = NODEID)
        RC.node_stat = '200'
        RC.save()

    @classmethod
    def init(self):
        '''更新任务类型'''
        MT = models.TaskType
        for name,f in self.tasklist.items():
            try:
                R = MT.get(MT.task_name == f['name'])
            except MT.DoesNotExist:
                R = MT(task_name = f['name'])
            R.task_desc = f['doc']
            R.task_type = f['type']
            R.save()

        '''更新插件'''
        PluginsManage.load('./payloads')
        MP = models.TaskPlugins
        MV = models.Vulnerable
        for plug in BaseHostPlugin.payloads() + BaseWebPlugin.payloads():
            if plug.bugname == ('',):
                continue
            RV,cd = MV.get_or_create(vul_name = plug.bugname)
            if cd:
                RV.vul_rank = plug.bugrank
                RV.vul_desc = plug.bugdesc
                RV.vul_plan = plug.bugplan
                RV.vul_number = plug.bugnumber
                RV.save()
            R,cd = MP.get_or_create(plug_name = plug.__class__.__name__)
            if cd:
                R.updatedate = datetime.datetime.now()
            R.vulid = RV
            R.plug_desc = plug.bugname
            R.plug_type = plug.__class__.__base__
            R.plug_file = plug.__class__
            R.save()

    @classmethod
    def loop(self):
        def gettask():
            M = models.ScanTask
            start = True
            while not self.Queue.full():
                logging.load('Waiting-Task: [%s]'%time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()))
                sw = (M.task_code == 'waiting')
                if start:
                    sw |= (M.task_code == 'PENDING')
                for Q in (M.select().where(sw).order_by(M.task_level,M.createdate)).limit(self.count):
                    self.Queue.put(Q)
                    Q.task_code = 'PENDING'
                    Q.save()
                start = False
                time.sleep(1)

        t = threading.Thread(target=gettask)
        t.start()
        while self.count:
            Q = self.Queue.get()
            p = multiprocessing.Process(target=self.addtask,args=(Q,False,))
            p.start()


if __name__ == '__main__':
    pass