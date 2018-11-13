#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


from __future__ import division
from functools import reduce
from urllib import parse
import os
import sys
import re
import signal
import time
import datetime
import json
import uuid
import traceback
import hashlib
import binascii
from tornado import web
from tornado.web import RequestHandler
from tornado.websocket import WebSocketHandler
import xlrd
import settings
import models
from service import TaskManage
from core.reportlib import ReportParse,ReportGenerate
from core.nmapscan import PortScan
DEBUG = settings.DEBUG

def generateid():
    return str(uuid.uuid4().hex)

def ormstr(s,sv=False):
    s = str(s)
    if s and s != 'None':
        if sv:
            s = s.replace('&','&amp;')
            s = s.replace('<','&lt;')
            s = s.replace('>','&gt;')
    else:
        s = ''
    return s.strip()

class MemorySession(object):
    '''会话管理器
    基于内存存储，每次服务器重启都要重新登录一次，
    以后要拓展再加入本地存储或者上redis
    初始化：session = MemorySession(token)
    设置值：value = session['key']
    取值：  session['key'] = value
    '''
    _session_data = {
        'userid':'@',
        'group':3,
        'projectid':'@'
    } if DEBUG else {}

    def __init__(self, token):
        self.session = token
    def __setitem__(self, key, value):
        if self.session not in self._session_data.keys():
            self.session = self.generate()
            self._session_data[self.session] = {}
        self._session_data[self.session][key] = value
    def __getitem__(self, key):
        info = self._session_data.get(self.session,{})
        if info:return info.get(key, None)
    def __str__(self):
        return str(self.session)
    @classmethod
    def generate(self):
        return str(generateid())
    def heartbeat(self):
        session = self.session
        self.session = self.generate()
        if session in self._session_data.keys():
            self._session_data[self.session] = self._session_data[session]
            del self._session_data[session]
        return str(self.session)

class Route(object):
    '''路由管理器
    使用负载均衡时，后端同时启用多路进程，管理器自动匹配主机
    注册：@Route(urlpattern)
    使用：Route.routes()
    '''
    _routes = {}
    def __init__(self, pattern, kwargs={}, name=None, host='.*$'):
        self.pattern = pattern #'/api' + pattern
        self.kwargs = {}
        self.name = name
        self.host = host
    def __call__(self, handler_class):
        spec = web.url(self.pattern, handler_class, self.kwargs, name=self.name)
        self._routes.setdefault(self.host, []).append(spec)
        return handler_class
    @classmethod
    def routes(cls, application=None):
        if application:
            for host, handlers in cls._routes.items():
                application.add_handlers(host, handlers)
        else:
            return reduce(lambda x,y:x+y, cls._routes.values()) if cls._routes else []

class Authenticated(object):
    '''权限管理器'''
    def __init__(self,group=0):
        self.group = group
    def __call__(self,f):
        def F(cls,d):
            #简单判断当前权限，后续再拓展
            if cls.session['group']:
                if int(cls.session['group']) >= int(self.group):
                    return f(cls,d)
                else:
                    cls.json['code'] = 401
                    cls.json['error'] = '权限不足'
            else:
                cls.json['code'] = 401
                cls.json['error'] = '您已退出登录'
            #cls.session.heartbeat()
        return F

class ApiAction(object):
    @Authenticated(2)
    def _bugdatabymouth_action(self,data):
        '''获取月统计数据'''
        projectid = data.get('projectid',None)

        M = models.BugResult
        MU = models.User
        MP = models.Project
        MT = models.ScanTask
        MV = models.Vulnerable

        RU = MU.get(MU.uid == self.session['userid'])
        sw = MP.project_user == RU
        if projectid:
            sw &= (MP.project_id == projectid)

        query = MP.select().where(sw).order_by(-MP.finishdate).limit(5)
        ret ={}
        ret_day = {}
        ret_mouth = {}
        ret_rank = {}
        mouthlist = set()
        daylist = set()
        for p in query:
            sw = (M.projectid == p)

            ret_mouth[str(p.project_name)] = {}
            query_mouth = (M
                .select(
                    models.orm.fn.substr(M.updatedate,1,7).alias('mouth'),
                    models.orm.fn.Count(M.bug_id).alias('count'))
                .where(sw)
                .group_by(models.orm.fn.substr(M.updatedate,1,7))
                .order_by(-M.updatedate)
                .limit(12))
            for q in query_mouth:
                mouthlist.add(str(q.mouth))
                ret_mouth[str(p.project_name)].update({str(q.mouth):str(q.count)})
            #ret['mouthvalue'] = ret_mouth

            ret_day[str(p.project_name)] = {}
            query_mouth = (M
                .select(
                    models.orm.fn.substr(M.updatedate,1,10).alias('daym'),
                    models.orm.fn.Count(M.bug_id).alias('count'))
                .where(sw)
                .group_by(models.orm.fn.substr(M.updatedate,1,10))
                .order_by(-M.updatedate)
                .limit(30))
            for q in query_mouth:
                daylist.add(str(q.daym)[:10])
                ret_day[str(p.project_name)].update({str(q.daym)[:10]:str(q.count)})
            #ret['dayvalue'] = ret_day

        '''
        for m in mouthlist:
            for p,v in ret_mouth.items():
                if m not in ret_mouth[p].keys():
                    ret_mouth[p][m] = 0
        for m in daylist:
            for p,v in ret_day.items():
                if m not in ret_day[p].keys():
                    ret_day[p][m] = 0
        '''
        ret['mouthvalue'] = ret_mouth
        ret['dayvalue'] = ret_day
        return ret
    @Authenticated(2)
    def _bugdatabypid_action(self,data):
        '''获取按漏洞名称统计数据'''
        projectid = data.get('projectid',None)

        M = models.BugResult
        MU = models.User
        MP = models.Project
        MT = models.ScanTask
        MV = models.Vulnerable

        RU = MU.get(MU.uid == self.session['userid'])
        sw = MP.project_user == RU
        if projectid:
            sw &= (MP.project_id == projectid)

        ret = {}
        #漏洞状态
        query_state = (M
            .select(M.bug_state,models.orm.fn.Count(M.bug_id).alias('count'))
            .switch(M)
            .join(MP)
            .where(sw)
            .group_by(M.bug_state))
        ret_state = {}
        for q in query_state:
            ret_state[str(q.bug_state)] = str(q.count)
        ret['statevalue'] = ret_state

        sw &= M.bug_state != '已修复'
        sw &= M.bug_state != '已忽略'

        #漏洞名称
        query_name = (M
            .select(MV.vul_name,models.orm.fn.Count(M.bug_id).alias('count'))
            .join(MV)
            .group_by(MV.vul_name)
            .switch(M)
            .join(MP)
            .where(sw)
            .order_by(MV.vul_name)
            .limit(8))
        ret_name = {}
        for qn in query_name:
            ret_name[str(qn.vulid.vul_name)] = str(qn.count)
        ret['namevalue'] = ret_name
        #漏洞等级
        query_rank = (M
            .select(MV.vul_rank,models.orm.fn.Count(M.bug_id).alias('count'))
            .join(MV)
            .group_by(MV.vul_rank)
            .switch(M)
            .join(MP)
            .where(sw)
            .order_by(MV.vul_rank))
        ret_rank  = {}
        for q in query_rank:
            ret_rank[str(q.vulid.vul_rank)] = str(q.count)
        ret['rankvalue'] = ret_rank
        return ret

    @Authenticated(2)
    def _portdatabypid_action(self,data):
        '''端口服务分布'''
        projectid = data.get('projectid')

        MU = models.User
        MP = models.Project
        MT = models.ScanTask
        MH = models.HostResult
        MR = models.PortResult

        RU = MU.get(MU.uid == self.session['userid'])
        sw = MP.project_user == RU
        if projectid:
            sw &= (MP.project_id == projectid)

        ret = {}
        ret['port'] = {}
        query_port = (MR
            .select(MR.port,models.orm.fn.Count(MR.port))
            .group_by(MR.port)
            .join(MH)
            .switch(MP)
            .join(MP)
            .where(sw)
        )
        for q in query_port:
            ret['port'][port] = str(q.count)

        return ret

    @Authenticated(2)
    def _taskdiff_action(self,data):
        '''任务对比'''
        class Bug(dict):
            def order(self):
                return (self['bugname'],self['bugaddr'])
            def __eq__(self,bug):
                return self.order() == bug.order()
            def __hash__(self):
                return hash(self.order())

        tida = data.get('tida')
        tidb = data.get('tidb')

        MB = models.BugResult
        MV = models.Vulnerable
        MT = models.ScanTask

        R1 = MT.get(MT.task_id == tida)
        R2 = MT.get(MT.task_id == tidb)
        querya = [Bug({
            "bugid":str(R.bug_id),
            "bugname":str(R.vulid.vul_name),
            "bugrank":str(R.vulid.vul_rank),
            "bugaddr":str(R.bug_addr),
            "bugstate":str(R.bug_state),
            "createdate":str(R.createdate)
        }) for R in MB.select().where(MB.taskid==R1).order_by(-MB.createdate)]
        queryb = [Bug({
            "bugid":str(R.bug_id),
            "bugname":str(R.vulid.vul_name),
            "bugrank":str(R.vulid.vul_rank),
            "bugaddr":str(R.bug_addr),
            "bugstate":str(R.bug_state),
            "createdate":str(R.createdate)
        }) for R in MB.select().where(MB.taskid==R2).order_by(-MB.createdate)]

        ret = {}
        inter = [] #交集
        union = [] #差集
        if querya and queryb:
            for R1 in querya:
                for R2 in queryb:
                    if(R1 == R2):
                        R2["bugstate"] = R1["bugstate"]
                        inter.append(R2)
                    elif R2 not in union and R2 not in querya:
                        union.append(R2)
        elif queryb:
            union = queryb

        ret["inter"] = inter
        ret["union"] = union
        return ret

    def _userlogin_action(self,data):
        '''用户登录，验证码还没有写'''
        username = data.get('u')
        password = data.get('p')
        verifycode = data.get('v')
        M = models.User
        try:
            R = M.get(M.username == username)#, M.password == M._create_password(password))
            if R._check_password(password):
                R.lastlogin = datetime.datetime.now()
                R.save()
                self.session['userid'] = str(R.uid)
                self.session['group'] = str(R.group)
                self.session['projectid'] = str(R.projectid)
                return {
                    'username'  :str(R.username),
                    'token'     :str(self.session),
                    'group'     :str(R.group),
                    'projectid' :self.session['projectid']
                }
            else:
                self.json['code'] = 401
                self.json['error'] = ' 用户名或密码错误'
        except M.DoesNotExist:
            self.json['code'] = 401
            self.json['error'] = '用户名或密码错误 '

####################项目管理####################################
    @Authenticated(1)
    def _projectselect_action(self,data):
        '''选择默认项目'''
        projectid = data.get('projectid')

        MP = models.Project
        MU = models.User
        if projectid:
            RP = MP.get(MP.project_id == projectid)
            RP.finishdate = datetime.datetime.now()
            RP.save()
            RU = MU.update(
                    projectid = str(RP.project_id)
                 ).where(
                    MU.uid == self.session['userid']
                 ).execute()
            self.session['projectid'] = str(RP.project_id)
            return {
                'projectid'     :str(RP.project_id),
                'projectname'   :str(RP.project_name)
            }

    @Authenticated(2)
    def _projectfinish_action(self,data):
        '''删除/禁用项目'''
        projectid = data.get('selectlist',[])

        M = models.Project
        MT = models.ScanTask

        for pid in projectid:
            M.update(
                finishdate = '0000-00-00 00:00:00'
            ).where(
                M.project_id == pid
            ).execute()
            #停止该项目所在的任务
            for Q in MT.select().join(M).where((M.project_id == pid)&((MT.task_code == 'PENDING')|(MT.task_code == 'waiting'))):
                TaskManage.stoptask(str(Q.task_pid))

    @Authenticated(2)
    def _projectadd_action(self,data):
        '''增加项目'''
        project_name = data.get('project_name')
        project_desc = data.get('project_desc')

        MP = models.Project
        MU = models.User
        R = MP.create(
                project_name = project_name,
                project_desc = project_desc,
                project_user = MU.get(MU.uid == self.session['userid'])
            )
        return {
            'project_id'    :str(R.project_id),
            'project_name'  :str(R.project_name),
            'project_desc'  :str(R.project_desc),
            'createdate'    :str(R.createdate),
            'createuser'    :str(R.project_user.realname),
        }

    @Authenticated(1)
    def _projectget_action(self,data):
        '''获取用户项目列表'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',10)

        MP = models.Project
        MS = models.ScanTask
        MB = models.BugResult
        MU = models.User
        MM = models.Member

        createuser = MU.get(MU.uid == self.session['userid'])
        sw = MP.project_user == createuser
        pidlist = [str(p.projectid.project_id) for p in MM.select().where(MM.userid == createuser)]
        if pidlist:
            sw |= MP.project_id << pidlist
        sw &= (MP.finishdate != '0000-00-00 00:00:00')
        if keyword:
            sw &= (MP.project_name.contains(keyword)|MP.project_desc.contains(keyword))
        query = (MP.select()
                   .where(sw)
                   .order_by(-MP.finishdate))
        ret = []
        for R in query.paginate(page, size):
            task = []
            for r in MS.select().where((MS.projectid == R)&(MS.finishdate != '0000-00-00 00:00:00')):
                task.append({
                    'desc':str(r.tasktype.task_desc),
                    'load':str(r.task_code)
                })

            bug = []
            bug += [v for v in MB.select().where(MB.projectid == R)]

            ret.append({
                'project_id'    :str(R.project_id),
                'project_name'  :str(R.project_name),
                'project_desc'  :str(R.project_desc),
                'createuser'    :str(R.project_user.realname),
                'member'        :[str(Q.userid.realname) for Q in MM.select().where(MM.projectid == R)],
                'createdate'    :str(R.createdate),
                'scanvul'       :len(bug),
                'scantask'      :len(task),
                'tasklist'      :list(set([d['desc'] for d in task])),
                'project_load'  :round((len([d for d in task if d['load']=='finish'])/len(task))*100,2) if task else 0
            })
        return ret


    @Authenticated(3)
    def _projectsget_action(self,data):
        '''获取所有项目列表'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',10)

        MP = models.Project
        MS = models.ScanTask
        MB = models.BugResult
        MU = models.User
        MM = models.Member

        sw = MP.project_id
        if keyword:
            sw &= (MP.project_name.contains(keyword)|MP.project_desc.contains(keyword))

        query = (MP.select()
                   .where(sw)
                   .order_by(-MP.finishdate))

        ret = []
        for R in query.paginate(page, size):
            task = []
            for r in MS.select().where((MS.projectid == R)&(MS.finishdate != '0000-00-00 00:00:00')):
                task.append({
                    'desc':str(r.tasktype.task_desc),
                    'load':str(r.task_code)
                })

            bug = []
            bug += [v for v in MB.select().where(MB.projectid == R)]

            ret.append({
                'project_id'    :str(R.project_id),
                'project_name'  :str(R.project_name),
                'project_desc'  :str(R.project_desc),
                'createuser'    :str(R.project_user.realname),
                'member'        :[str(Q.userid.realname) for Q in MM.select().where(MM.projectid == R)],
                'createdate'    :str(R.createdate),
                'scanvul'       :len(bug),
                'scantask'      :len(task),
                'tasklist'      :list(set([d['desc'] for d in task])),
                'project_load'  :round((len([d for d in task if d['load']=='finish'])/len(task))*100,2) if task else 0
            })
        return ret

    @Authenticated(2)
    def _projectinfo_action(self,data):
        '''项目详情'''
        projectid = data.get('projectid')

        MP = models.Project
        MS = models.ScanTask
        MV = models.VulResult

        R = MP.get(MP.project_id == projectid)

        task = []
        query = (MS.select().where((MS.projectid ==R)&(MS.finishdate != '0000-00-00 00:00:00')))
        for r in query:
            task.append({
                'taskid'    :str(r.task_id),
                'taskcode'  :str(r.task_code),
                'taskhost'  :str(r.task_host),
                'taskargs'  :str(r.task_args),
                'tasknote'  :str(r.task_note),
                'tasklevel' :str(r.task_level),
                'taskname'  :str(r.tasktype.task_desc),
                'createdate':str(r.createdate),
                'finishdate':str(r.finishdate),
            })
        return {
            'projectid'     :str(R.project_id),
            'project_name'  :str(R.project_name),
            'project_desc'  :str(R.project_desc),
            'createuser'    :str(R.project_user.realname),
            'createdate'    :str(R.createdate),
            'finishdate'    :str(R.finishdate),
            'scantask'      :task,
        }

    @Authenticated(1)
    def _projectsearchbyname_action(self,data):
        '''根据项目名称搜索'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',10)

        MP = models.Project
        MU = models.User
        MM = models.Member

        createuser = MU.get(MU.uid == self.session['userid'])
        sw = MP.project_user == createuser
        pidlist = [str(p.projectid.project_id) for p in MM.select().where(MM.userid == createuser)]
        if pidlist:
            sw |= MP.project_id << pidlist
        sw &= MP.finishdate != '0000-00-00 00:00:00'
        if keyword:
            sw &= MP.project_name.contains(keyword)

        query = (MP.select()
                  .where(sw)
                  .order_by(MP.createdate))

        ret = []
        for Q in query.paginate(page, size):
            ret.append({
                'id'    :str(Q.project_id),
                'name'  :str(Q.project_name),
            })
        return ret

    @Authenticated(2)
    def _psettingedit_action(self,data):
        '''项目设置'''
        editd = data.get('editd')
        pid = data.get('pid')
        pname = data.get('pname')
        pdesc = data.get('pdesc')
        pmembers = data.get('pmembers',[])
        pusers = data.get('pusers',[])
        ppwds = data.get('ppwds',[])

        MU = models.User
        MP = models.Project
        MD = models.DictResult
        MM = models.Member

        RU = MU.get(MU.uid==self.session['userid'])
        RP = MP.get((MP.project_user==RU)&(MP.project_id == pid))
        if pname or editd:
            RP.project_name = pname
        if pdesc or editd:
            RP.project_desc = pdesc
        RP.save()

        if editd:
            MD.delete().where((MD.projectid==RP)&(MD.dict_key == 'user')).execute()
            MD.delete().where((MD.projectid==RP)&(MD.dict_key == 'pwd')).execute()
            MM.delete().where(MM.projectid ==RP).execute()
        for user in pusers:
            MD.get_or_create(projectid=RP,dict_key='user',dict_value=user)
        for pwd in ppwds:
            MD.get_or_create(projectid=RP,dict_key='pwd',dict_value=pwd)
        for member in pmembers:
            MM.get_or_create(projectid=RP,userid=MU.get(MU.uid==member['uid']))

        pusers = [str(Q.dict_value) for Q in MD.select().where((MD.projectid==RP)&(MD.dict_key == 'user'))]
        pwds = [str(Q.dict_value) for Q in MD.select().where((MD.projectid==RP)&(MD.dict_key == 'pwd'))]
        pmembers = [{
            'uid':str(Q.userid.uid),
            'username':str(Q.userid.username),
            'realname':str(Q.userid.realname)
        } for Q in MM.select().where(MM.projectid==RP)]

        ret = {}
        ret['pusers'] = pusers
        ret['ppwds'] = pwds
        ret['pmembers'] = pmembers
        ret['pname'] = str(RP.project_name)
        ret['pdesc'] = str(RP.project_desc)
        return ret

######################任务管理##################################################
    @Authenticated(3)
    def _tasktypeget_action(self,data):
        '''获取任务类型'''
        tasktype = data.get('type','')
        page = data.get('page',1)
        size = data.get('size',100)

        M = models.TaskType
        sw = M.task_type != '-1'
        if tasktype:
            sw &= M.task_type == tasktype
        query = M.select().where(sw)
        ret = []
        for R in query:
            ret.append({
                'task_name':str(R.task_name),
                'task_desc':str(R.task_desc),
                'task_type':str(R.task_type),
            })
        return ret
    @Authenticated(3)
    def _tasknodeget_action(self,data):
        '''获取任务节点'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',100)

        M = models.ClientNode
        sw = M.node_stat == '200'
        if keyword:
            sw &= M.node_id.contains(keyword)
        query = M.select().where(sw)
        ret = []
        for R in query:
            ret.append({
                'nodeid':str(R.node_id),
                'nodestat':str(R.node_stat),
                'nodeauth':str(R.node_auth),
            })
        return ret
    @Authenticated(2)
    def _scantasksearch_action(self,data):
        '''本项目任务列表'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',50)

        MS = models.ScanTask
        MP = models.Project

        sw = (MP.project_id==self.session['projectid'])
        sw &= (MS.task_code != 'stop' )
        if keyword:
            sw &= (MS.task_id.contains(keyword))|(MS.task_host.contains(keyword))|(MS.task_note.contains(keyword))
        query = (MS.select()
                   .join(MP)
                   .where(sw)
                   .order_by(-MS.createdate)
                )
        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for R in query.paginate(page, size):
            ret.append({
                'task_id'   :str(R.task_id),
                'task_code':str(R.task_code),
                'task_host':str(R.task_host),
                'task_name':str(R.tasktype.task_desc),
                'task_args':str(R.task_args),
                'createdate':str(R.createdate)[:10],
            })
        result['ret'] = ret
        return result
    @Authenticated(2)
    def _scantaskadd_action(self,data):
        '''新建任务'''
        task_host = data.get('task_host')
        task_name = data.get('task_name',[])
        task_level = data.get('task_level',3)
        task_args = data.get('task_args')
        task_note = data.get('task_note')
        task_node = data.get('task_node')

        MS = models.ScanTask
        MP = models.Project
        MT = models.TaskType
        MC = models.ClientNode
        RP = MP.get(MP.project_id == self.session['projectid'])

        for name in task_name:
            try:
                RT = MT.get(MT.task_name == name)
            except:
                continue
            for host in task_host.split():
                if task_node:
                    for node in task_node:
                        RC = MC.get(MC.node_id == task_node)
                        R = MS.create(
                            projectid = RP,
                            tasktype = RT,
                            tasknode = RC,
                            task_host = host,
                            task_args = task_args,
                            task_note = task_note,
                            task_level = task_level)
                        TaskManage.addtask(R)
                else:
                    R = MS.create(
                            projectid = RP,
                            tasktype = RT,
                            task_host = host,
                            task_args = task_args,
                            task_note = task_note,
                            task_level = task_level)
                    TaskManage.addtask(R)
    @Authenticated(2)
    def _scantaskfinish_action(self,data):
        '''删除任务'''
        tasklist = data.get('selectlist',[])

        M = models.ScanTask
        MB = models.BugResult
        for tid in tasklist:
            R1 = M.get(M.task_id == tid)
            R2 = MB.delete().where(MB.taskid==R1).execute()
            R1.delete_instance()
            TaskManage.stoptask(R1.task_pid)
    @Authenticated(2)
    def _scanntaskinfo_action(self,data):
        '''任务详情'''
        taskid = data.get('taskid')
        page = data.get('page',1)
        size = data.get('size',50)

        MS = models.ScanTask
        MB = models.BugResult

        R = MS.get(MS.task_id == taskid)
        buglist = [{
            'bugid':str(bug.bug_id),
            'bugname':str(bug.vulid.vul_name),
            'bugrank':str(bug.vulid.vul_rank)} \
            for bug in (MB
                        .select()
                        .where(MB.taskid == R)
                        .order_by(MB.updatedate))]
        return {'buglist'   :buglist,
                'taskid'    :str(R.task_id),
                'taskcode'  :str(R.task_code),
                'taskhost'  :str(R.task_host),
                'taskargs'  :str(R.task_args),
                'tasknote'  :str(R.task_note),
                'taskpid'   :str(R.task_pid),
                'tasklevel' :str(R.task_level),
                'taskname'  :str(R.tasktype.task_desc),
                'tasktype'  :str(R.tasktype.task_name),
                'tasknode'  :str(R.tasknode.node_id if R.tasknode else ''),
                'createdate':str(R.createdate),
                'finishdate':str(R.finishdate),
            }


#####################漏洞管理########################################
    @Authenticated(1)
    def _buginfoget_action(self,data):
        '''获取漏洞详情'''
        bugid = data.get('bugid')
        M = models.BugResult
        R = M.get(M.bug_id == bugid)
        return {
            'projectid':    str(R.projectid.project_id),
            'projectname':  str(R.projectid.project_name),
            'createuser':   str(R.userid.realname),
            #'taskid':       str(R.taskid.task_id),
            'bugid':        str(R.bug_id),
            'bugaddr':      str(R.bug_addr),
            'bugstate':     str(R.bug_state),
            'bugtag':       [v for v in str(R.bug_tag).split('|')],
            'bugreq':       str(R.request).replace('on','0n'),
            'bugres':       str(R.response),
            'createdate':   str(R.createdate),
            'updatedate':   str(R.createdate),
            'vulinfo':{
                'vulid':        str(R.vulid.vul_id),
                'vulrank':      str(R.vulid.vul_rank),
                'vulname':      str(R.vulid.vul_name),
                'vulreal':      str(R.vulid.vul_real),
                'vulowasp':     str(R.vulid.vul_owasp),
                'vulno':    [v for v in str(R.vulid.vul_number).split('|')],
                'vuldesc':      str(R.vulid.vul_desc),
                'vulplan':      str(R.vulid.vul_plan),
            }
        }
    @Authenticated(1)
    def _stepinfoget_action(self,data):
        '''获取漏洞处理进度'''
        bugid = data.get('bugid')
        MF = models.BugFlow
        MB = models.BugResult
        query = MF.select().where(
                    MF.flowid == MB.get(MB.bug_id == bugid)
                ).order_by(MF.createdate)
        ret=[]
        for R in query:
            ret.append({
                'flowid'    : str(R.fid),
                'flowname'  : str(R.flowname.realname),
                'updatedate': str(R.createdate),
                'flownote'  : str(R.flownote),
            })
        return ret
    @Authenticated(1)
    def _stepsave_action(self,data):
        '''编辑漏洞进度'''
        bugid = data.get('bugid')
        note = data.get('note')

        MF = models.BugFlow
        MB = models.BugResult
        MU = models.User

        R = MF.create(
                flowid = MB.get(
                    MB.bug_id == bugid),
                flowname = MU.get(
                    MU.uid == self.session['userid']),
                flownote = note
            )
        return {
            'flowid'    : str(R.fid),
            'flowname'  : str(R.flowname.realname),
            'updatedate': str(R.createdate),
            'flownote'  : str(R.flownote),
        }

    @Authenticated(1)
    def _bugsearch_action(self,data):
        '''搜索漏洞'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',30)
        history = data.get('history',False)

        MB = models.BugResult
        MV = models.Vulnerable
        MP = models.Project

        sw = MB.id
        if history:
            sw = ((MB.bug_state == '已修复')|(MB.bug_state == '已忽略'))
        else:
            sw &= (MB.bug_state != '已修复')
            sw &= (MB.bug_state != '已忽略')
        if keyword:
            sw &= (MV.vul_name.contains(keyword) \
                | MV.vul_real.contains(keyword) \
                | MB.bug_id.contains(keyword) \
                | MB.bug_addr.contains(keyword))

        query = (MB
                .select()
                .join(MP)
                .where(MP.project_id == self.session['projectid'])
                .switch(MB)
                .join(MV)
                .where(sw)
                .order_by(-MB.updatedate))

        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for Q in query.paginate(page, size):
            ret.append({
                'bugid':str(Q.bug_id),
                'bugrank':str(Q.vulid.vul_rank),
                'bugname':str(Q.vulid.vul_name),
                'bugaddr':str(Q.bug_addr),
                'bugstate':str(Q.bug_state),
                'updatedate':str(Q.updatedate),
            })
        result['ret'] = ret
        return result

    @Authenticated(2)
    def _bugdelete_action(self,data):
        '''删除漏洞'''
        buglist = data.get('selectlist',[])
        MB = models.BugResult
        MF = models.BugFlow

        for bug in buglist:
            R = MB.get(MB.bug_id == bug)
            MF.delete().where(MF.flowid == R).execute()
            R.delete_instance()

    @Authenticated(2)
    def _bugfinish_action(self,data):
        '''确认修复'''
        buglist = data.get('selectlist',[])
        M = models.BugResult
        MF = models.BugFlow
        MU = models.User

        RU = MU.get(MU.uid == self.session['userid'])
        for bug in buglist:
            try:
                R = M.get(M.bug_id == bug)
                R.bug_state = '已修复'
                R.updatedate = datetime.datetime.now()
                R.save()
                MF.create(
                    flowid = R,
                    flowname = RU,
                    flownote = R.bug_state,
                )
            except:
                pass

    @Authenticated(2)
    def _bugfalse_action(self,data):
        '''确认忽略'''
        buglist = data.get('selectlist',[])
        M = models.BugResult
        MF = models.BugFlow
        MU = models.User

        RU = MU.get(MU.uid == self.session['userid'])
        for bug in buglist:
            try:
                R = M.get(M.bug_id == bug)
                R.bug_state = '已忽略'
                R.updatedate = datetime.datetime.now()
                R.save()
                MF.create(
                    flowid = R,
                    flowname = RU,
                    flownote = R.bug_state,
                )
            except:
                pass

    @Authenticated(1)
    def _bugedit_action(self,data):
        '''漏洞更新'''
        projectid = data.get('projectid',self.session['projectid'])
        vulid = data.get('vulid')
        bugid = data.get('bugid')

        MB = models.BugResult
        MP = models.Project
        MS = models.ScanTask
        MV = models.Vulnerable
        MT = models.TaskType
        MU = models.User

        RP = MP.get(MP.project_id == projectid)

        try:
            R = MB.get(MB.bug_id == bugid)
        except MB.DoesNotExist:
            R = MB()
            RU = MU.get(MU.uid == self.session['userid'])
            RS,cd = MS.get_or_create(
                        task_host = '@',
                        task_code = 'finish',
                        projectid = RP,
                        tasktype = MT.get(MT.task_name == 'handwork')
                    )
            R.taskid = RS
            R.userid = RU
        R.projectid = RP
        R.vulid = MV.get(MV.vul_id == vulid)
        R.bug_addr = data.get('bugaddr')
        R.request = data.get('bugreq')
        R.bug_tag = data.get('bugtag','')
        R.bug_note = data.get('bugnote','')
        R.updatedate = datetime.datetime.now()
        R.save()
        return {'bugid':str(R.bug_id),'bugname':str(R.vulid.vul_name)}
    @Authenticated(1)
    def _bugimport_action(self,data):
        '''导入漏洞'''
        fids = data.get('fids')

        M = models.BugResult
        MP = models.Project
        MS = models.ScanTask
        MT = models.TaskType
        MV = models.Vulnerable
        MU = models.User
        RP = ReportParse()

        userid = MU.get(MU.uid == self.session['userid'])
        projectid = MP.get(MP.project_id == self.session['projectid'])
        tasktype = MT.get(MT.task_name == 'automatic')
        for fid in fids:
            if not fid or not re.match("^([a-fA-F0-9]{32})$",fid):
                self.finish('参数错误')
                return
            RS,cd = MS.get_or_create(
                        task_host = fid,
                        task_code = 'finish',
                        projectid = projectid,
                        tasktype = tasktype)
            try:
                RP.load(settings.UPLOADPATH +'/'+ fid)
            except Exception as e:
                RS.task_code = str(e)
                RS.save()
            for r in RP.output():
                RV,cd = MV.get_or_create(
                    vul_name = r.get('bugname')
                )
                if cd:
                    RV.vul_desc = r.get('bugdesc')
                    RV.vul_real = r.get('bugname')
                    RV.vul_plan = r.get('bugplan')
                    RV.vul_rank = r.get('bugrank')
                    RV.vul_owasp = r.get('bugowasp')
                    RV.vul_number = r.get('bugnumber')
                    RV.save()
                M.create(
                    taskid = RS,
                    vulid = RV,
                    userid = userid,
                    projectid = projectid,
                    bug_addr = r.get('bugaddr'),
                    bug_tag = r.get('bugtag'),
                    bug_note = r.get('bugnote'),
                    request = r.get('bugreq'),
                    response = r.get('bugres'),
                )
        return str(RS.task_id)

###############用户管理#################################
    @Authenticated(3)
    def _mentsearch_action(self,data):
        '''搜索部门'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',50)

        M = models.Department
        query = M.select().where(
                    M.name.contains(keyword)
                ).order_by(M.createdate).paginate(page, size)

        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for Q in query:
            ret.append({
                'bid':str(Q.bid),
                'name':str(Q.name),
                'time':str(Q.createdate),
            })
        result['ret'] = ret
        return result
    @Authenticated(3)
    def _mentedit_action(self,data):
        '''编辑部门'''
        M = models.Department
        R,cd = M.get_or_create(name = data.get('name'))
        return {
            'cd':cd,
            'bid':str(R.bid),
            'name':str(R.name),
            'time':str(R.createdate),
        }
    @Authenticated(3)
    def _mentdelete_action(self,data):
        '''删除部门'''
        selectlist = data.get('selectlist')
        MU = models.User
        MD = models.Department

        for bid in selectlist:
            R = MD.get(M.bid == bid)
            R.delete_instance()

################################################################
    @Authenticated(3)
    def _useredit_action(self,data):
        '''用户更新'''
        M = models.User
        MD = models.Department
        try:
            R = M.get(M.uid == data.get('uid'))
        except M.DoesNotExist:
            R = M()
        R.department = MD.get(MD.bid == data.get('department'))
        R.group = data.get('group',1)
        R.username = data.get('username')
        R.company = data.get('company','')
        R.realname = data.get('realname','')
        R.phone = data.get('phone','')
        R.email = data.get('email','')
        R.save()
        return {
            'uid':str(R.uid),
            'username':str(R.username),
            'group':str(R.group),
            'company':str(R.company),
            'mentid':str(R.department.bid),
            'mentname':str(R.department.name),
            'realname':str(R.realname),
            'phone':str(R.phone),
            'email':str(R.email),
        }

    @Authenticated(3)
    def _userdelete_action(self,data):
        '''删除用户'''
        userlist = data.get('selectlist')
        M = models.User
        MM = models.Member

        for user in userlist:
            R = M.get(M.uid == user)
            MM.delete().where(MM.userid == R).execute()
            R.delete_instance()

    @Authenticated(3)
    def _usersearch_action(self,data):
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',50)

        M = models.User
        sw = M.uid
        if keyword:
            sw = (M.username.contains(keyword)) \
               | (M.realname.contains(keyword)) \
               | (M.company.contains(keyword))  \
               | (M.phone.contains(keyword))
        query = M.select().where(sw).order_by(M.createdate)

        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for Q in query.paginate(page, size):
            ret.append({
                'uid':str(Q.uid),
                'username':str(Q.username),
                'group':str(Q.group),
                'company':str(Q.company),
                'department':str(Q.department.name),
                'realname':str(Q.realname),
                'phone':str(Q.phone),
                'email':str(Q.email),
            })
        result['ret'] = ret
        return result
#######################插件管理############################################
    @Authenticated(3)
    def _pluginedit_action(self,data):
        '''插件状态编辑'''
        selectlist = data.get('selectlist',[])
        M = models.TaskPlugins
        for p in selectlist:
            M.update(
                plug_stat = p.get('plugstat',True)
            ).where(
                M.plug_name == p.get('plugname')
            ).execute()

    @Authenticated(3)
    def _pluginsearch_action(self,data):
        '''插件搜索'''
        page = data.get('page',1)
        size = data.get('size',30)
        keyword = data.get('keyword')

        M = models.TaskPlugins

        sw = M.id
        if keyword:
            sw = (M.plug_name.contains(keyword) \
                | M.plug_desc.contains(keyword) \
                |(M.plug_file == keyword) \
                |(M.plug_type == keyword) )

        query = (M.select().where(sw).order_by(-M.updatedate))

        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for Q in query.paginate(page, size):
            ret.append({
                #"vulid":        str(Q.vulid.vul_id),
                "plugname":     str(Q.plug_name),
                "plugdesc":     str(Q.plug_desc),
                "plugtype":     str(Q.plug_type),
                "plugfile":     str(Q.plug_file),
                "updatedate":   str(Q.updatedate),
                "_checked":     str(Q.plug_stat),
            })
        result['ret'] = ret
        return result
####################基础漏洞管理####################################################
    @Authenticated(1)
    def _vulsearch_action(self,data):
        '''基础漏洞列表'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',30)

        M = models.Vulnerable
        sw = (M.updatedate !=1 )
        if keyword:
            sw &= (M.vul_name.contains(keyword) \
                  |M.vul_real.contains(keyword) \
                  |M.vul_number.contains(keyword))
        query = (M.select()
                .where(sw)
                .order_by(-M.updatedate))

        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for Q in query.paginate(page, size):
            ret.append({
                'vulid':str(Q.vul_id),
                'vulname':str(Q.vul_name),
                'vulreal':str(Q.vul_real),
                'vulplan':str(Q.vul_plan),
                'vulrank':str(Q.vul_rank),
                'vuldesc':str(Q.vul_desc),
                'vulowasp':str(Q.vul_owasp),
                'vulno':str(Q.vul_number),
            })
        result['ret'] = ret
        return result

    @Authenticated(3)
    def _vuledit_action(self,data):
        vulid = data.get('vulid')
        M = models.Vulnerable
        cd = False
        try:
            R = M.get(M.vul_id == vulid)
        except M.DoesNotExist:
            R = M()
            cd = True
        R.vul_name = data.get('vulname')
        R.vul_real = data.get('vulname')
        R.vul_rank = data.get('vulrank','')
        R.vul_owasp = data.get('vulowasp','')
        R.vul_number = data.get('vulno','')
        R.vul_desc = data.get('vuldesc','')
        R.vul_plan = data.get('vulplan','')
        R.updatedate = datetime.datetime.now()
        R.save()
        return {
            'created':cd,
            'vulid':str(R.vul_id),
            'vulname':ormstr(R.vul_real) or ormstr(R.vul_name),
            'vulplan':str(R.vul_plan),
            'vulrank':str(R.vul_rank),
            'vulowasp':str(R.vul_owasp),
            'vulno':str(R.vul_number),
            'vuldesc':str(R.vul_desc),
        }
    @Authenticated(3)
    def _vuldelete_action(self,data):
        vullist = data.get('selectlist')
        M = models.Vulnerable
        #for vul in vullist:
        #    #M.delete().where(M.vul_id == vul).execute()
        #    M.update(updatedate=1).where(M.vul_id == vul).execute()

#####################资产管理####################################
    @Authenticated(3)
    def _servicesearch_action(self,data):
        '''获取服务列表'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',50)

        M = models.PortResult
        query = M.select().where(
                    M.service_name.contains(keyword)
                ).group_by(M.service_name).order_by(-M.updatedate)
        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for R in query.paginate(page, size):
            ret.append({
                'name':str(R.service_name)
            })
        result['ret'] = ret
        return result

    @Authenticated(2)
    def _hostsearch_action(self,data):
        '''获取项目资产列表'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',30)

        M = models.PortResult
        MH = models.HostResult
        MP = models.Project

        project = MP.get(MP.project_id == self.session['projectid'])

        sw = MH.updatedate != '0000-00-00 00:00:00'
        sw &= MH.projectid == project
        query = MH.select()
        if keyword:
            sw = (MH.host_ip.contains(keyword) \
                 |MH.host_name.contains(keyword) \
                 |MH.mac_addr.contains(keyword) \
                 |MH.note.contains(keyword) \
                 |M.service_name.contains(keyword) \
                 |M.soft_name.contains(keyword) \
                 |M.soft_ver.contains(keyword) \
                 |M.response.contains(keyword))
            if keyword.isdigit():
                sw = M.port.contains(keyword)
            query = query.join(M)

        query = query.where(sw).group_by(MH.host_ip)
        #print(query)
        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for RH in query.paginate(page, size):
            ret.append({
                'hostid'    : str(RH.host_id),
                'hostip'    : str(RH.host_ip),
                'hostname'  : str(RH.host_name),
                #'ostype'    : str(RH.os_type),
                'osver'     : str(RH.os_version),
                #'macaddr'   : str(RH.mac_addr),
                #'phyaddr'   : str(RH.phy_addr),
                'note'      : str(RH.note),
            })
        result['ret'] = ret
        return result

    @Authenticated(2)
    def _hostfinish_action(self,data):
        '''删除主机'''
        hostid = data.get('hostid')
        M = models.HostResult
        M.update(updatedate = '0000-00-00 00:00:00').where(M.host_id == hostid).execute()

    @Authenticated(2)
    def _hostedit_action(self,data):
        '''主机资料更新'''
        hostid = data.get('hostid')

        MH = models.HostResult
        MP = models.Project
        MU = models.User

        try:
            R = MH.get(MH.host_id == hostid)
        except MH.DoesNotExist:
            R = MH()
            R.host_id == hostid
            R.projectid = MP.get(MP.project_id == self.session['projectid'])
            R.userid = MU.get(MP.uid == self.session['userid'])
        R.host_ip = data.get('hostip')
        R.host_name = data.get('hostname')
        R.os_type = data.get('ostype')
        R.os_version = data.get('osver')
        R.mac_addr = data.get('macaddr')
        R.phy_addr = data.get('phyaddr')
        R.note = data.get('note')
        R.updatedate = datetime.datetime.now()
        R.save()
        return str(R.host_ip)
    @Authenticated(2)
    def _hostimport_action(self,data):
        '''导入主机'''
        fids = data.get('fids')

        MH = models.HostResult
        MP = models.Project
        MU = models.User

        user = MU.get(MU.uid == self.session['userid'])

        projectid = MP.get(MP.project_id == self.session['projectid'])
        for fid in fids:
            if not fid or not re.match("^([a-fA-F0-9]{32})$",fid):
                self.finish('参数错误')
                return
            ret = {}
            path = settings.UPLOADPATH +'/'+ fid
            with open(path,'rb') as f:
                content = f.read()
            #nmap xml
            if b'<!DOCTYPE nmaprun>' in content:
                ret = PortScan.parse_report(str(content))
            #手工 xlsx
            elif b'workbook.xml' in content:
                workbook = xlrd.open_workbook(path)
                sheet = workbook.sheet_by_index(0)
                for i in range(1,sheet.nrows):
                    host = sheet.row(i)[0].value
                    port = str(int(sheet.row(i)[3].value))
                    if host not in ret.keys():
                        ret[host] = {}
                        ret[host]['ports'] = set()
                    ret[host]['hostname'] = sheet.row(i)[1].value
                    ret[host]['ostype'] = sheet.row(i)[2].value
                    ret[host]['mac'] = ''
                    ret[host]['status'] = 'up'
                    ret[host]['ports'].add((
                        host,
                        port,
                        'tcp',
                        'open',
                        sheet.row(i)[4].value,
                        '',
                        '',
                        sheet.row(i)[5].value,
                        sheet.row(i)[6].value))

            for host,value in ret.items():
                RH,created      = MH.get_or_create(projectid = projectid, userid = user, host_ip = host)
                if created:
                    RH.host_name    = value['hostname']
                    #RH.os_version   = value['status']
                    RH.mac_addr     = value['mac']
                RH.updatedate   = datetime.datetime.now()
                RH.note         = value['status']
                RH.os_type      = value['ostype']
                RH.save()
                for host,port,protocol,state,service,product,extrainfo,version,data in value['ports']:
                    RP,created      = models.PortResult.get_or_create(host=host,port=port)
                    if created:
                        RP.hostid       = RH
                        RP.port_type    = protocol
                        RP.port_state   = state
                        RP.service_name = service
                        RP.soft_name    = product
                        RP.soft_type    = extrainfo
                        RP.soft_ver     = version
                        RP.response     = str(data)
                    RP.updatedate   = datetime.datetime.now()
                    RP.save()

    @Authenticated(1)
    def _portlistget_action(self,data):
        '''获取主机对应端口'''
        hostid = data.get('hostid')
        MH = models.HostResult
        MR = models.PortResult

        RH = MH.get()

        query = MR.select().join(MH).where(MH.host_id == hostid).order_by(MR.port)
        ret = []
        for RP in query:
            ret.append({
                'port'      : str(RP.port),
                'service'   : str(RP.service_name),
                'softname'  : str(RP.soft_name),
                'softtype'  : str(RP.soft_type),
                'softver'   : str(RP.soft_ver),
                'note'      : str(RP.response),
            })
        return ret

    @Authenticated(2)
    def _portfinish_action(self,data):
        '''删除端口'''
        hostid = data.get('hostid')
        port = data.get('port')

        MP = models.PortResult
        MH = models.HostResult

        MP.delete().where(
            (MP.host == MH.get(MH.host_id == hostid))&(MP.port == port)
        ).execute()

    @Authenticated(2)
    def _portedit_action(self,data):
        '''端口资料更新'''
        hostid = data.get('hostid')
        port = data.get('port')

        MH = models.HostResult
        MP = models.PortResult

        RH = MH.get(MH.host_id == hostid)

        try:
            R = MP.get(MP.hostid == RH, MP.port == port)
        except MP.DoesNotExist:
            R = MP()
            R.host = RH
            R.host_ip = RH.host_ip
            R.port = port
        R.service_name = data.get('service')
        R.soft_name = data.get('softname')
        R.soft_type = data.get('softtype')
        R.soft_ver = data.get('softver')
        R.response = data.get('note')
        R.updatedate = datetime.datetime.now()
        R.save()
        return str(R.port)
    @Authenticated(2)
    def _portadd_action(self,data):
        '''手工增加资产'''
        MR = models.PortResult
        MH = models.HostResult
        MP = models.Project
        MU = models.User

        RH,cd = MH.get_or_create(
                host_ip = data.get('hostip'),
                projectid = MP.get(MP.project_id == self.session['projectid']))
        RH.userid = MU.get(MU.uid == self.session['userid'])
        RH.host_name = data.get('hostname')
        RH.os_version = data.get('osver')
        RH.updatedate = datetime.datetime.now()
        RH.save()

        try:
            RP = MR.get(MR.hostid == RH, MR.port == data.get('hostport'))
        except MR.DoesNotExist:
            RP = MR()
            RP.hostid = RH
            RP.host = RH.host_ip
            RP.port = data.get('hostport')
        RP.service_name = data.get('service')
        RP.soft_ver = data.get('softver')
        RP.response = data.get('note')
        RP.updatedate = datetime.datetime.now()
        RP.save()

    @Authenticated(3)
    def _httpsearch_action(self,data):
        '''HTTP'''
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',30)

        M = models.HttpResult
        sw = M.id
        if keyword:
            sw = (M.host.contains(keyword) \
                 |M.domain.contains(keyword) \
                 |M.title.contains(keyword) \
                 |M.banner.contains(keyword) \
                 |M.xpoweredby.contains(keyword) \
                 |M.headers.contains(keyword) \
                 |M.content.contains(keyword))
            if keyword.isdigit():
                sw = M.port == keyword
        query = (M.select()
                  .where(sw)
                  .order_by(-M.updatedate))
        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for R in query.paginate(page, size):
            ret.append({
                'host'    : str(R.host),
                'port'    : str(R.port),
                'domain'  : str(R.domain),
                'state'   : str(R.state),
                'headers' : str(R.headers),
                'content' : [v for v in str(R.content).split('|') if v],
                'title'   : str(R.title),
                'updatedate' : str(R.updatedate)[:10],
            })
        result['ret'] = ret
        return result

    @Authenticated(3)
    def _portsearch_action(self,data):
        '''获取所有资产列表'''
        page = data.get('page',1)
        size = data.get('size',30)
        keyword = data.get('keyword')
        ment = data.get('ment')
        user = data.get('user')
        service = data.get('service')
        port = data.get('port')

        M = models.PortResult
        MH = models.HostResult
        MP = models.Project
        MU = models.User
        MD = models.Department


        sw = M.updatedate != '0000-00-00 00:00:00'
        query = M.select()
        if port:
            sw &= M.port == port
        if service:
            sw &= M.service_name == service
        if keyword:
            sw &= (MH.host_ip.contains(keyword) \
                 |MH.host_name.contains(keyword) \
                 |MH.mac_addr.contains(keyword) \
                 |MH.note.contains(keyword) \
                 |M.soft_name.contains(keyword) \
                 |M.soft_ver.contains(keyword) \
                 |M.response.contains(keyword))

        query = query.join(MH).where(sw)

        if ment:
            ment = MD.get(MD.bid == ment)
            sw = MU.department == ment
            if user:
                sw |= MU.uid == user
            query = query.join(MU).where(sw)

        query = query.order_by(-M.updatedate)
        #print(query)
        result = {}
        result['current'] = page
        result['total'] = query.count()
        ret = []
        for R in query.paginate(page, size):
            ret.append({
                'ment'      : str(R.hostid.userid.department.name),
                'user'      : "%s(%s)"%(str(R.hostid.projectid.project_user.username),str(R.hostid.projectid.project_user.realname)),
                'hostip'    : str(R.host),
                'port'      : str(R.port),
                'service'   : str(R.service_name),
                'softver'   : ''.join(str(R.soft_ver).split(',')),
            })
        result['ret'] = ret
        return result

########################################################################################
    @Authenticated(1)
    def _getmessage_action(self,data):
        '''获取站内信'''
        msgstat = data.get('msgstat','0')
        keyword = data.get('keyword')
        page = data.get('page',1)
        size = data.get('size',50)

        M = models.Message
        MU = models.User
        RU = MU.get(MU.uid == self.session['userid'])
        ret = []
        sw = M.recvid == RU
        if msgstat:
            sw &= M.msgstate == msgstat
        for R in M.select().where(sw).order_by(-M.senddate,M.msgstate).paginate(page,size):
            ret.append({
                'msgid'     :str(R.msgid),
                'title'     :str(R.msgtitle),
                'content'   :str(R.msgcontent),
                'sendid'    :str(R.sendid.username),
                'senddate'  :str(R.senddate),
            })

        return {'message':ret}
    @Authenticated(1)
    def _sendmessage_action(self,data):
        '''发送站内消息'''
        msgtitle = data.get('title')
        msgcontent = data.get('content')
        recvid = data.get('rid',[])

        M = models.Message
        MU = models.User
        RU = MU.get(MU.uid == self.session['userid'])
        for rid in recvid:
            try:
                recvid = MU.get(MU.uid == rid)
                M.create(
                    sendid = RU,
                    recvid = recvid,
                    msgtitle = msgtitle,
                    msgcontent = msgcontent,
                )
            except Exception as e:
                pass
    @Authenticated(1)
    def _setmessagestat_action(self,data):
        '''站内信状态标记'''
        msgid = data.get('msgid')
        msgstat = data.get('msgstat','1')
        assert msgstat in ['-1','0','1'] #-1 回收站，0 未读，1 已读
        M = models.Message
        MU = models.User

        RU = MU.get(MU.uid == self.session['userid'])
        R = M.get(M.msgid == msgid,M.recvid == RU)
        R.msgstate = msgstat
        R.recvdate = datetime.datetime.now()
        R.save()
    @Authenticated(1)
    def _getmsgcontent_action(self,data):
        '''获取消息详情'''
        msgid = data.get('msgid')

        M = models.Message
        MU = models.User
        RU = MU.get(MU.uid == self.session['userid'])
        R = M.get(M.msgid == msgid,M.recvid == RU)

        return {
            'msgid'     :str(R.msgid),
            'title'     :str(R.msgtitle),
            'content'   :str(R.msgcontent),
            'sendid'    :str(R.sendid.username),
            'senddate'  :str(R.senddate),
            'msgstat'   :str(R.msgstate)
        }



#################################################################################################3

class BaseHandler(RequestHandler):
    def initialize(self):
        self.session = {}
        if models.userdata.is_closed():
            models.userdata.connect()

    def on_finish(self):
        if not models.userdata.is_closed():
            models.userdata.close()

    def set_default_headers(self):
        self.set_header("X-Powered-By","PHP/6.6.6")
        self.set_header("Server","Apache/6.6.6")
        self.set_header("Date","EMM, 00 SB 2333 00:00:00 MMM")
        if DEBUG:
            self.set_header("Access-Control-Allow-Credentials","true")
            self.set_header("Access-Control-Allow-Origin","*")

    def write_error(self, status_code, **kwargs):
        self.finish("<h1>%d</h1>" % status_code)

    def get_current_user(self):
        return True


#####################################################################################################

@Route(r'/api.php')
class ApiHandler(BaseHandler,ApiAction):

######################################################################################
    def _heartbeat_action(self,data):
        '''安全心跳包
        1、发送该心跳包后要使用返回的token才能继续请求
        '''
        return {'token':self.session.heartbeat()}

    def _hacker_action(self,data):
        self.json['code'] = 502
        self.json['error'] = data.get("msg","BurpSuite Rce Exp Mdzz")

######################################################################################
    @web.authenticated
    @web.asynchronous
    def post(self):
        """ 全局处理函数，传入json
            形式如下
                {'c':'action', 'd':{data}}
        """
        data = self._decryptdata()
        #self.session = MemorySession(data.get('t',None))
        act = data.get('c','')
        kvs = data.get('d',{})
        self.json = {}
        self.json['code'] = 200
        self.json['error'] = ''
        action = '_' + act + '_action'
        if hasattr(self,action):
            try:
                self.json['result'] = getattr(self,action)(kvs)
            except Exception as e:
                self.json['error'] = str(e)
                if DEBUG:
                    type,value,tb = sys.exc_info()
                    e = '\n'.join(set(traceback.format_exception(type,value,tb)))
                print(str(e))
                self.json['code'] = 500
        else:
            self.json['code'] = 404
            self.json['error'] = '找不到该方法'
        self.set_status(self.json['code'])
        self.write(self._encryptdata(self.json))
        self.finish()

    def _decryptdata(self,key=None):
        now = int(time.time()*1000)
        hash = self.request.headers.get('Control','i')
        data = self.request.body
        hash,token = hash[:32],hash[32:]
        if hashlib.sha1(data).hexdigest()[4:36] == hash:
            body = json.loads(data.decode())
            if (now - int(body['s'][::-1],16)) <= 1000*6*60*6:  #超过6s则视为无效
                self.session = MemorySession(token)
                return body
        return {'c':'hacker'}

    def _decryptdata1(self,key=None):
        now = int(time.time()*1000)
        hash = self.request.headers.get('Hash','i')
        data = self.request.body
        sha1 = hashlib.sha1(data).hexdigest()[4:36]
        token = self.__xor(sha1,hash)
        body = json.loads(data.decode())
        if (now - int(body['s'][::-1],16)) <= 6666:  #超过6s则视为无效
            self.session = MemorySession(token)
            return body
        return {'c':'hacker'}

    def _encryptdata(self,data,key=None):
        #return binascii.b2a_hex(str(data).encode())
        return data

    def __xor(self, msg, key):
        data = []
        for i in range(len(key)):
            m_index = i % len(msg)
            m_key = msg[m_index]
            data +=  chr(ord(key[i]) ^ ord(m_key))
        return "".join(data)




#############################################################################################


@Route(r'/upload.php')
class UploadHandler(BaseHandler):
    @web.authenticated
    @web.asynchronous
    def get(self):
        '''文件下载'''
        fid = self.get_argument('fid')
        if not fid or not re.match("^([a-fA-F0-9]{32})$",fid):
            self.finish('参数错误')
            return
        path = os.path.join(settings.UPLOADPATH, fid.group(0))
        with open(path,'rb') as fr:
            self.set_header('Content-Type','text/plain')
            self.write(fr.read())
        self.finish()

    #@web.authenticated
    @web.asynchronous
    def post(self):
        def _writefile(meta):
            file_id = str(uuid.uuid4().hex)
            path = os.path.join(settings.UPLOADPATH, file_id)
            with open(path, 'wb') as fw:
                fw.write(meta['body'])
            return file_id

        ret = {}
        ret['code'] = 200
        ret['error'] = 0
        ret['result'] = []
        for name,file_metas in self.request.files.items():
            for mate in file_metas:
                fd = {}
                fd['fname'] = mate['filename']
                fd['fid'] = _writefile(mate)
                ret['result'].append(fd)
        self.write(ret)
        self.finish()



####################################################################################################################

@Route(r'/report.php')
class ReportHandler(BaseHandler):
    @web.asynchronous
    def get(self):
        self.post()

    @web.asynchronous
    def post(self):
        '''报告生成'''
        def readreport(path):
            with open(path,'rb') as fr:
                while True:
                    data = fr.read(1024)
                    if not data:
                        break
                    self.write(data)

        pid = self.get_argument('pid')
        tid = self.get_argument('tid')
        cid = self.get_argument('cid','1') #是否强制生成报告
        fty = self.get_argument('fty','doc') #生成报告类型

        if not(pid and tid):
            self.finish('参数错误')
            return

        self.session = MemorySession(tid)
        MT = models.ScanTask
        MP = models.Project
        MB = models.BugResult
        MU = models.User
        MM = models.Member

        createuser = MU.get(MU.uid == self.session['userid'])
        projectid = MP.get((MP.project_user == createuser)&(MP.project_id == pid))

        buglist = []
        state = set()
        for R in (MB.select()
                    .where(MB.projectid == projectid)
                    .order_by(MB.updatedate)):
            rank = ormstr(R.vulid.vul_rank,sv=True)
            state.add(rank)
            buglist.append({
                'bugrank':      rank,
                'bugname':      ormstr(R.vulid.vul_real,sv=True) or ormstr(R.vulid.vul_name,sv=True),
                'bugowasp':     ormstr(R.vulid.vul_owasp,sv=True),
                'bugnumber':    ormstr(R.vulid.vul_number,sv=True),
                'bugdesc':      ormstr(R.vulid.vul_desc,sv=True),
                'bugplan':      ormstr(R.vulid.vul_plan,sv=True),
                'bugid':        ormstr(R.bug_id,sv=True),
                'bugaddr':      ormstr(R.bug_addr,sv=True),
                'bugstate':     ormstr(R.bug_state,sv=True),
                'bugtag':       ormstr(R.bug_tag,sv=True),
                'bugreq':       ormstr(R.request,sv=True),
                'bugres':       ormstr(R.response,sv=True),
                'bugnote':      ormstr(R.bug_note,sv=True),
                'bugstate':     ormstr(R.bug_state,sv=True),
                'createdate':   ormstr(R.createdate)[:10],
                'updatedate':   ormstr(R.createdate)[:10],
            })

        projectstate = '良好状态'
        if '中危' in state:
            projectstate = '预警状态'
        if '高危' in state:
            projectstate = '严重状态'
        if '紧急' in state:
            projectstate = '紧急状态'
        
        projectinfo = {
            'projectid'     :ormstr(projectid.project_id,sv=True),
            'projectname'   :ormstr(projectid.project_name,sv=True),
            'projectdesc'   :ormstr(projectid.project_desc,sv=True),
            'createuser'    :ormstr(projectid.project_user.realname,sv=True),
            'memberuser'    :'、'.join([ormstr(Q.userid.realname,sv=True) for Q in MM.select().where(MM.projectid == projectid)]),
            'createemail'   :ormstr(projectid.project_user.email,sv=True),
            'createtel'     :ormstr(projectid.project_user.phone,sv=True),
            'createdate'    :ormstr(projectid.createdate,sv=True)[:10],
            'finishdate'    :ormstr(datetime.datetime.now(),sv=True)[:10],
            'state':        projectstate,
            'buglist':      buglist
        }

        if fty == 'doc':
            #不创建直接读取数据库里面的path
            path = str(projectid.reportpath)
            if(cid == '0')and(os.path.isfile(path)):
                readreport(path)
                self.finish()
                return
            filename = parse.quote("report-%s.docx"%str(projectid.project_id))
            self.set_header('Content-Type','application/octet-stream')
            self.set_header('Content-Disposition', 'attachment; filename=' + filename)
            RG = ReportGenerate(projectinfo,os.path.join(settings.REPORTPATH ,"basereport.docx"))
            path = os.path.join(settings.REPORTPATH,ormstr(projectid.project_id)+'.docx')
            path = RG.save(path)
            projectid.reportpath = path
            projectid.save()
            readreport(path)
        elif fty=='json':
            self.set_header('Content-Type','application/json')
            self.write(json.loads(projectinfo))
        self.finish()

###########################################################################################################

@Route(r'/.*')
class IndexHandler(BaseHandler,ApiAction):
    def get(self):
        self.render("index.html")

@Route(r'/log')
class WebSocket(BaseHandler,WebSocketHandler):
    def on_message(self,msg):
        pass

    def on_close(self):
        pass

class Application(web.Application):
    def __init__(self):
        web.Application.__init__(
            self, handlers = Route.routes(), **settings.SETTINGS)


def main():
    from tornado import ioloop
    from tornado.httpserver import HTTPServer
    from tornado.options import define, options, parse_command_line

    def runserver():
        http_server = HTTPServer(Application(), xheaders=True)
        http_server.listen(options.port)
        loop = ioloop.IOLoop.instance()

        def shutdown():
            print('Server stopping ...')
            http_server.stop()
            print('IOLoop wil  be terminate in 1 seconds')
            deadline = time.time() + 1

            def terminate():
                now = time.time()
                if now < deadline and (loop._callbacks or loop._timeouts):
                    loop.add_timeout(now + 1, terminate)
                else:
                    loop.stop()
                    print('Server shutdown')
            terminate()

        def sig_handler(sig, frame):
            print('Caught signal:%s', sig)
            loop.add_callback(shutdown)

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)

        print('Server running on http://0.0.0.0:%d'%(options.port))
        loop.start()

    define('port', default=8315, type=int)
    parse_command_line()
    runserver()

if __name__ == '__main__':
    main()
