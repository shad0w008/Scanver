#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      ydhcui@/QQ664284092

from lib import sql as orm
from settings import DATABASE
import time
import datetime
import uuid
import hashlib

class MySQLDatabase(orm.MySQLDatabase):
    '''解决mysql连接超时'''
    def execute_sql(self, sql, params=None, commit=True):
        try:
            cursor = super(orm.MySQLDatabase, self).execute_sql(sql, params, commit)
        except orm.OperationalError:
            if not self.is_closed():
                self.close()
            with orm.__exception_wrapper__:
                cursor = self.cursor()
                cursor.execute(sql, params or ())
                if commit and not self.in_transaction():
                    self.commit()
        return cursor

if DATABASE['datatype']=='mysql':
    userdata = MySQLDatabase(
        DATABASE['dataname'],
        host     = DATABASE['datahost'],
        port     = DATABASE['dataport'],
        user     = DATABASE['username'],
        passwd   = DATABASE['password'],
        charset  = DATABASE['charset'])
elif DATABASE['datatype']=='sqlite':
    userdata = orm.SqliteDatabase(
        DATABASE['datapath'])

def generateid():
    return str(uuid.uuid4().hex)

class BaseModel(orm.Model):
    class Meta:
        database = userdata

class ClientNode(BaseModel):
    '''节点信息表，自动更新'''
    node_id = orm.CharField(unique = True)  #节点ID
    node_stat = orm.CharField(null=True)    #节点状态
    node_auth = orm.CharField(null=True)    #节点校验码

class TaskType(BaseModel):
    """任务类型表，自动更新"""
    task_name = orm.CharField(unique = True)      #任务名称
    task_desc = orm.CharField(null=True)          #任务描述
    task_type = orm.CharField(default = '-1')     #任务类型

class Vulnerable(BaseModel):
    '''基础漏洞表'''
    vul_id      = orm.CharField(unique = True, max_length = 32, default = generateid)
    vul_name    = orm.CharField(unique = True)                      #漏洞名称 - 原名，索引用。
    vul_real    = orm.CharField(null = True, default = '')          #漏洞别名 - 翻译过的中文名
    vul_rank    = orm.CharField(null = True, default = '')          #漏洞等级
    vul_plan    = orm.CharField(null = True, default = '')          #修复建议
    vul_desc    = orm.CharField(null = True, default = '')          #漏洞描述
    vul_owasp   = orm.CharField(null = True, default = '')          #owasp对应关系
    vul_number  = orm.CharField(null = True, default = '')          #漏洞编号 CWE/CVE/CNVD/CNNVD
    updatedate  = orm.DateTimeField(default = datetime.datetime.now)

class TaskPlugins(BaseModel):
    """扫描插件表，自动更新"""
    vulid       = orm.ForeignKeyField(Vulnerable, related_name = 'TaskPlugins_vulid', null = True) #每个插件对应一个漏洞
    plug_name   = orm.CharField(unique = True)                      #插件名称
    plug_desc   = orm.CharField(null=True, default = '')            #插件描述
    plug_type   = orm.CharField(null=True, default = '')            #插件类型 1-host,2-web,3-http
    plug_file   = orm.CharField(null=True, default = '')            #插件文件名、路径
    plug_stat   = orm.BooleanField(default = True)                  #是否启用
    updatedate  = orm.CharField(default = datetime.datetime.now)

class Department(BaseModel):
    '''部门表'''
    bid         = orm.CharField(unique = True, max_length = 32, default = generateid)
    name        = orm.CharField(unique = True, max_length = 32)         #部门名称
    createdate  = orm.DateTimeField(default = datetime.datetime.now)    #创建时间

class User(BaseModel):
    '''用户表'''
    uid         = orm.CharField(unique = True, max_length = 32, default = generateid)
    username    = orm.CharField(unique = True, max_length = 32)        #用户名
    password    = orm.CharField(                                       #用户密码
        max_length = 32,
        default = "103006226e74df7e96e59bc24eb973e7"
    )
    group       = orm.IntegerField(default = 1)                         #3-系统管理员，2-管理员，1-普通用户
    company     = orm.CharField(null = True, default = '')              #所在公司
    department  = orm.ForeignKeyField(Department, related_name = 'User_Departmentid')#部门
    realname    = orm.CharField(null = True, max_length = 32)           #真实姓名
    phone       = orm.CharField(null = True, max_length = 11)           #电话
    email       = orm.CharField(null = True, default='TOPSEC@COM.CN')   #邮箱
    createdate  = orm.DateTimeField(default = datetime.datetime.now)    #创建时间
    lastlogin   = orm.DateTimeField(default = datetime.datetime.now)    #最后登录时间
    projectid   = orm.CharField(null = True, default = '')              #上次选择的项目

    def _check_password(self, raw, salt='\t\o\p\s\e\c'):
        return hashlib.md5(raw.encode() + salt.encode()).hexdigest() == self.password

    @staticmethod
    def _create_password(raw,salt='\t\o\p\s\e\c'):
        return hashlib.md5(hashlib.sha256(raw.encode()).hexdigest().encode()
             + salt.encode()).hexdigest()

class Project(BaseModel):
    '''项目/系统表'''
    project_id  = orm.CharField(unique = True, max_length = 32, default = generateid)
    project_name= orm.CharField(null = True, default = '')                                      #项目名称
    project_desc= orm.CharField(null = True, default = '')                                      #项目描述
    project_node= orm.ForeignKeyField(ClientNode, related_name = 'Project_nodeid', null = True) #任务节点-对应tasknode中的名称
    project_user= orm.ForeignKeyField(User, related_name = 'Project_createuser')                #项目经理
    developer   = orm.ForeignKeyField(User, related_name='developer', null = True)              #开发商
    maintainer  = orm.ForeignKeyField(User, related_name='maintainer', null = True)             #维护商
    reportpath  = orm.CharField(null=True, default = '0')                                       #报告导出的路径
    createdate  = orm.DateTimeField(default = datetime.datetime.now)                            #
    finishdate  = orm.DateTimeField(default = '0000-00-00 00:00:00')                            #1-表示删除该项目

class Member(BaseModel):
    '''项目成员表'''
    projectid   = orm.ForeignKeyField(Project, related_name='Member_projectid')
    userid      = orm.ForeignKeyField(User, related_name='Member_userid')

class DictResult(BaseModel):
    '''项目字典'''
    projectid   = orm.ForeignKeyField(Project, related_name = 'DictResult_projectid')
    dict_key    = orm.CharField(default = '')
    dict_value  = orm.CharField(default = '')
    dict_style  = orm.CharField(default = 'ALL')
    dict_count  = orm.IntegerField(default = 1)     #引用计数

class ScanTask(BaseModel):
    '''扫描任务表'''
    projectid   = orm.ForeignKeyField(Project, related_name = 'ScanTask_projectid',)
    tasktype    = orm.ForeignKeyField(TaskType, related_name = 'ScanTask_tasktype', null = True)  #任务名称-对应tasktype中的名称
    tasknode    = orm.ForeignKeyField(ClientNode, related_name = 'ScanTask_nodeid', null = True)  #任务节点-对应tasknode中的名称
    task_id     = orm.CharField(unique = True, max_length = 32, default = generateid)
    task_host   = orm.CharField()                                #任务主机
    task_args   = orm.CharField(null=True, default = '')         #任务参数
    task_note   = orm.CharField(null=True, default = '')         #备注
    task_code   = orm.CharField(default = 'waiting')             #任务状态 waiting-等待运行，working-运行中，finish-已完成，pause-进程挂起，，-
    task_pid    = orm.CharField(null=True, default = '',)        #任务对应的id
    task_level  = orm.IntegerField(null=True, default = 3,)      #任务等级 0、1、2、3
    createdate  = orm.DateTimeField(default = datetime.datetime.now)        #创建时间
    finishdate  = orm.DateTimeField(default = datetime.datetime.now)        #1-表示删除该任务

class HostResult(BaseModel):
    '''资产管理表'''
    projectid   = orm.ForeignKeyField(Project, related_name = 'HostResult_projectid',null = True,)
    userid      = orm.ForeignKeyField(User, related_name = 'HostResult_userid',null = True,)
    host_id     = orm.CharField(unique = True, max_length = 32, default = generateid)
    host_ip     = orm.CharField()                                #主机ip
    host_name   = orm.CharField(null = True, default = '')       #主机名
    os_type     = orm.CharField(null = True, default = '')       #系统类型
    os_version  = orm.CharField(null = True, default = '')       #系统版本
    mac_addr    = orm.CharField(null = True, default = '')       #mac地址
    phy_addr    = orm.CharField(null = True, default = '')       #物理地址
    note        = orm.CharField(null = True, default = '')       #备注
    updatedate  = orm.DateTimeField(default = datetime.datetime.now)

class PortResult(BaseModel):
    '''端口扫描结果'''
    hostid      = orm.ForeignKeyField(HostResult, related_name = 'PortResult_hostid',null = True,)
    host        = orm.CharField()                                #主机ip
    port        = orm.CharField()                                #主机端口
    port_type   = orm.CharField(null = True, default = '')       #端口类型 tcp/udp
    port_state  = orm.CharField(null = True, default = '')       #端口状态 open/close/filter
    service_name= orm.CharField(null = True, default = '')       #服务名称 http/mssql/ssh 。。
    soft_name   = orm.CharField(null = True, default = '')       #中间件名称
    soft_type   = orm.CharField(null = True, default = '')       #中间件类型
    soft_ver    = orm.CharField(null = True, default = '')       #中间件版本
    response    = orm.TextField(null = True, default = '')       #原始返回包
    isconfirm   = orm.BooleanField(default = False)              #人工审核
    updatedate  = orm.DateTimeField(default = datetime.datetime.now)

class HttpResult(BaseModel):
    '''WEB扫描结果表'''
    hostid      = orm.ForeignKeyField(HostResult, related_name = 'HttpResult_hostid',null = True,)
    host        = orm.CharField()
    port        = orm.IntegerField(null = True, default = 80)
    domain      = orm.CharField(null = True, default = '')
    state       = orm.IntegerField(null = True, default = 0)
    banner      = orm.CharField(null = True, default = '')
    xpoweredby  = orm.CharField(null = True, default = '' )
    title       = orm.CharField(null = True, default = '')
    headers     = orm.TextField(null = True, default = '{}' )
    content     = orm.TextField(null = True, default = '' )
    updatedate  = orm.DateTimeField(default = datetime.datetime.now)

class BugResult(BaseModel):
    '''漏洞扫描结果'''
    projectid   = orm.ForeignKeyField(Project, related_name='BugResult_projectid')              #项目id
    taskid      = orm.ForeignKeyField(ScanTask, related_name='BugResult_taskid',null = True)    #任务id
    hostid      = orm.ForeignKeyField(HostResult, related_name='BugResult_hostid',null = True)  #漏洞所属资产
    userid      = orm.ForeignKeyField(User, related_name='BugResult_userid',null = True)        #漏洞提交人
    vulid       = orm.ForeignKeyField(Vulnerable, related_name='BugResult_vulid')               #基础漏洞id
    bug_id      = orm.CharField(unique = True, max_length = 32, default = generateid)
    request     = orm.TextField(null = True, default = '')               #原始请求包漏洞详情
    response    = orm.TextField(null = True, default = '')               #原始返回包
    bug_addr    = orm.CharField(null = True, default = '')               #漏洞地址
    bug_state   = orm.CharField(default = '漏洞提交')                    #漏洞状态：漏洞提交、漏洞审核,漏洞修复,漏洞复查、已修复[已忽略]
    bug_tag     = orm.CharField(null = True, default = '')               #漏洞标签
    bug_note    = orm.CharField(null = True, default = '')               #备注
    createdate  = orm.DateTimeField(default = datetime.datetime.now)     #发现日期
    plandate    = orm.DateTimeField(default = datetime.datetime.now)     #计划修复日期
    updatedate  = orm.DateTimeField(default = datetime.datetime.now)     #复查日期

class BugFlow(BaseModel):
    '''漏洞跟踪表'''
    fid         = orm.PrimaryKeyField()                                        #跟踪自身id
    flowid      = orm.ForeignKeyField(BugResult, related_name='flowvulresult') #跟踪识别id
    flowname    = orm.ForeignKeyField(User, related_name='flowcontact')        #审批人员
    backstep    = orm.IntegerField(default = 0)                                #前一步流程ID
    nextstep    = orm.CharField(null = True, default = '')                     #后一步流程ID
    flowstate   = orm.BooleanField(default = True)                             #是否通过
    flownote    = orm.CharField(null = True)                                   #处理意见
    createdate  = orm.DateTimeField(default = datetime.datetime.now)

class Message(BaseModel):
    '''站内信'''
    sendid      = orm.ForeignKeyField(User, related_name='sendid_user')
    recvid      = orm.ForeignKeyField(User, related_name='recvid_user')
    msgid       = orm.CharField(unique = True, default = generateid)
    msgtitle    = orm.CharField(null = True, default = '')
    msgcontent  = orm.CharField(null = True, default = '')
    msgstate    = orm.CharField(default = '0')
    senddate    = orm.DateTimeField(default = datetime.datetime.now)
    recvdate    = orm.DateTimeField(default = datetime.datetime.now)

if __name__ == '__main__':
    def init():
        for name in BaseModel.__subclasses__():
            if not name.__name__.startswith('Base'):
               name.create_table(fail_silently=True)
        TaskType.get_or_create(task_name='handwork',task_desc=u'手工录入',task_type='-1')
        TaskType.get_or_create(task_name='automatic',task_desc=u'批量导入',task_type='-1')
    init()
    R,cd = Department.get_or_create(name='test')
    user,cd = User.get_or_create(username='sc',group=3, department=R, password=User._create_password('1111'))
    #user1,cd = User.get_or_create(username='admin',group=2,password=User._create_password('123456'))
    #user1,cd = User.get_or_create(username='user',group=1,password=User._create_password('123456'))
    #Project.get_or_create(project_id='@',project_user=user,project_name='互联网项目')

