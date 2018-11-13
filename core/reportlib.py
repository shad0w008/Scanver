#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092
from lib.docxtpl import DocxTemplate,InlineImage,RichText
from lib.docx import Document
from lib.docx.shared import Mm, Inches, Pt
from lib.jinja2 import Environment
import time
import re
import uuid
import csv
import base64
import io
import urllib.parse as urlparse

class ReportGenerate(object):
    def __init__(self, context, template,clear=True):
        self.doc = DocxTemplate(template)
        jinja_env = Environment()
        if clear:
            context['buglist'] = self.bugs_clear(context['buglist'])
        jinja_env.filters['eval'] = lambda x:eval(x,context)
        self.doc.render(context,jinja_env)

    def save(self, path):
        self.doc.save(path)
        return path

    def parse_xml(self, value):
        result = []
        texts  = re.findall("&lt;p&gt;(.*?)&lt;/p&gt;",value)
        for text in texts:
            img = re.findall(r'&lt;img src="data:image.*?;base64,(.*?)"',text)
            if img:
                img = io.BytesIO(base64.b64decode(img[0]))
                img_obj = InlineImage(self.doc, img, width=Mm(170))
                result.append(img_obj)
            else:
                rt_obj = text#RichText(text)
                result.append(rt_obj)
        return result

    def del_tag(self, s, tag):
        s = re.sub(r'&lt;{0}.*?&gt;(.*?)&lt;/{0}&gt;'.format(tag), '', s)
        s = re.sub(r'&lt;{0}.*?&gt;'.format(tag), '', s)
        return s

    def bugs_clear(self, bugs, clear_keys=['bugreq'], filter_tags=['br']):
        for i, bug in enumerate(bugs, 1):
            bug['num'] = str(i)
            for key, value in bug.items():
                if key in clear_keys:
                    if not value.startswith('&lt;p&gt;'):
                        value = '&lt;p&gt;%s&lt;/p&gt;'%value
                    for tag in filter_tags:
                        value = self.del_tag(value, tag)
                    bug[key] = self.parse_xml(value)
        return bugs

class ReportGenerateDoc(object):
    def __init__(self, template, **args):
        dirs = dir(self)
        for k, v in args.items():
            if k not in dirs:
                setattr(self, k, v)
            else:
                print('[!] already exist key: '+ k)
        self.doc  = Document(template)
        self.re_cmd = re.compile(r'{%(.*?)%}')
        self.re_bug = re.compile(r'{{(.*?)}}')
        self.bug_block_start = '<%bugblock_start%>'
        self.bug_block_end   = '<%bugblock_end%>'
        self.picture_width   = 5800000
        self.fill_info()


    def replace_cmd(self, obj):
        cmds = self.re_cmd.findall(obj.text)
        for cmd in cmds:
            try:
                result = str(eval(cmd.lower(), {'self':self}))
                obj.text = obj.text.replace('{%%%s%%}'%cmd, result)
            except:
                msg = '[!][{%%%s%%}] Invalid cmd in: %s'
                print(msg % (cmd, obj.text))


    def fill_info(self):
        for para in self.doc.paragraphs:
            self.pi = para
            self.replace_cmd(para)
        for tab in self.doc.tables:
            lineno = 0
            while True:
                cells = tab.row_cells(lineno)
                if not cells:
                    break
                for cell in cells:
                    for para in cell.paragraphs:
                        self.replace_cmd(para)
                lineno += 1


    def insert_picture_from(self, content):
        if content:
            flag = 'One who wants to wear the crown, Bears the crown. --- L-codes'
            self.pi.insert_paragraph_before(flag)
            for p in self.doc.paragraphs:
                if flag == p.text:
                    flag_p = p
                    break
            flag_p.clear()
            flag_p.add_run('')
            f = io.BytesIO(base64.b64decode(content))
            #with open(settings.UPLOADPATH +'/'+ fid, 'rb') as f:
            flag_p.runs[-1].add_picture(f, width=self.picture_width)


    def add_remain_bugs(self, bugs):
        for bug in bugs:
            for text, sty in self.bug_template:
                keys = self.re_bug.findall(text)
                islist_not_insert = False
                for key in keys:
                    result = bug.get(key,key)
                    if isinstance(result, list):
                        islist_not_insert = True
                        for tp, data in result:
                            if tp == 'text':
                                self.pi.insert_paragraph_before(data)
                            elif tp == 'img':
                                self.insert_picture_from(data)
                    else:
                        text = text.replace('{{%s}}'%key, result)
                if not islist_not_insert:
                    self.pi.insert_paragraph_before(text, style=sty)


    def add_bugs(self, bugs):
        if not bugs:
            print('[!] bugs is empty')
            return None
        is_bugblock = False
        self.bug_template = []
        bug, bugs = bugs[0], bugs[1:]
        for para in self.doc.paragraphs:
            self.pi = para
            if self.bug_block_end in para.text:
                is_bugblock = False
                para.clear()
                break
            if is_bugblock:
                self.bug_template.append((para.text, para.style))
                keys = self.re_bug.findall(para.text)
                for key in keys:
                    result = bug.get(key, key)
                    if isinstance(result, list):
                            for tp, data in result:
                                if tp == 'text':
                                    para.insert_paragraph_before(data)
                                elif tp == 'img':
                                    self.insert_picture_from(data)
                            self.pi.clear()
                    else:
                            para.text = para.text.replace('{{%s}}'%key, result)
            if self.bug_block_start in para.text:
                is_bugblock = True
                para.clear()
        self.add_remain_bugs(bugs)

    def save(self, path=None):
        path = path or '%s-pentestreport.docx' % self.projectname
        self.doc.save(path)
        return path

    @staticmethod
    def bugs_clear(bugs, clear_keys=['bugreq'], filter_tags=['br']):
        def parse_xml(value):
            result = []
            text  = re.compile(r'<p>(.*?)</p>')
            #image = re.compile(r'<img src="\./upload\.php\?fid=([a-z\d]{8}(?:-[a-z\d]{4}){3}-[a-z\d]{12})"')
            image = re.compile(r'<img src="data:.*?;base64,(.*?)"')
            for s in text.finditer(value):
                img = image.search(s[0])
                if img:
                    result.append(['img', img[1]])
                else:
                    result.append(['text', s[1]])
            return result
        def del_tag(s, tag):
            s = re.sub(r'<{0}.*?>(.*?)</{0}>'.format(tag), '', s)
            s = re.sub(r'<{0}.*?>'.format(tag), '', s)
            return s

        for i, bug in enumerate(bugs, 1):
            bug['num'] = str(i)
            for key, value in bug.items():
                if key in clear_keys:
                    for tag in filter_tags:
                        value = del_tag(value, tag)
                    bug[key] = parse_xml(value)
        return bugs

class ReportParse(object):
    def __init__(self):
        self.steam      = None
        self.content    = b''
        self.text       = ''
        self.buglist    = []
        #漏洞示例
        buginfo = {
            'bugaddr'   :'', #漏洞地址      （必须，可以是url地址或者某个IP地址对应端口如 http://127.0.0.1/bugaddr?id=1或 127.0.0.1:1433
            'bugreq'    :'', #原始请求包    （没有填空，
            'bugres'    :'', #原始返回结果  （没有填空，
            'bugtag'    :'', #漏洞标签      （没有填空，以|分隔，如 SQL|XSS|弱口令
            'bugnote'   :'', #漏洞备注      （没有填空，
            'bugname'   :'', #漏洞名称      （必须
            'bugrank'   :'', #漏洞等级      （必须，分四个等级【紧急，高危，中危，低危】 如果不是这个名称要进行相应转换
            'bugowasp'  :'', #owasp对应关系 （没有填空
            'bugnumber' :'', #漏洞编号      （没有填空，以|分隔，如 CVE-2017-12345|CNVD-2017-12345|CWE-17
            'bugdesc'   :'', #漏洞描述      （没有填空，
            'bugplan'   :'', #修复建议      （没有填空，
        }

    @classmethod
    def raw_html(self,html):
        dr = re.compile(r'<[^>]+>',re.S)
        html = dr.sub('',html)
        html = html.replace('\n','')
        html = html.replace('&#34;','\'')
        html = html.replace('&#39;','"')
        html = html.replace('&lt;','<')
        html = html.replace('&gt;','>')
        html = html.replace('\\r\\n','')
        html = html.replace('\\','')
        return html.strip()

    def output(self):
        t = self.buglist
        self.buglist = []
        return t

    def load(self,filepath,act= None):
        with open(filepath,'rb') as self.steam:
            self.content = self.steam.read()
            self.text = str(self.content)
            self.filepath = filepath
        if act:
            getattr(self,'handler_%s'%act)()
        else: #找到报告的唯一标识，并由此判断报告格式
            contentstr = str(self.content)
            if 'oOarNtAtTUO9U5IbGM8cQ0Kh0e0TqgAATRQGQTU' in contentstr:
                self.handler_topsec_html() #天融信html报告
            elif '37t3jD3v37l2ySYy5fft2JJ6vRxHueOTIEZwUeVVQUDBnzhz6duPGjXSokJAQqkeGFkyE3EE9r2fPnmRAnDj' in contentstr:
                self.handler_awvs_html_developer()
            elif 'GCPyoV4EKz927BjVDBgwoLq6mj8vCb9Ebt682Yh' in contentstr:
                self.handler_awvs_html() #awvs html报告
            elif 'jumpToHash(event.target.hash);' in contentstr:
                self.handler_nsfocus_html() #绿盟html报告
            elif '<title>Nessus Scan Report</title>' in contentstr:
                self.handler_nessus_html()
            elif 'Plugin Output' in contentstr:
                self.handler_nessus_csv()

    def handler_topsec_html(self):
        '''根据天融信漏洞扫描器html格式详细报告进行转换'''
        html_content = str(self.content,encoding='utf-8')

        addr = re.findall("IP/域名:(.*?)<",html_content)
        name = re.findall("='>(.*?)</a><td class='numLinkLow'>",html_content)
        desc = re.findall("<tr><td width='20%'>描述</td><td width='80%' >(.*?)</td></tr>",html_content)
        plan = re.findall("<tr><td width='20%'>解决办法</td><td width='80%' >(.*?)</td></tr>",html_content)
        cve  = re.findall("<tr><td width='20%'>CVE</td><td width='80%' >(.*?)<",html_content)
        cnvd =  re.findall("<tr><td width='20%'>CNVD</td><td width='80%' >(.*?)<",html_content)
        cnnvd= re.findall("<tr><td width='20%'>CNNVD</td><td width='80%' >(.*?)<",html_content)
        rank = re.findall("<tr><td width='20%'>风险级别</td><td width='80%'>(.*?)<",html_content)

        for  i  in range(len(name)):
            rank = rank[i].replace('低风险',   '低危') \
                          .replace('中风险',   '中危') \
                          .replace('高风险',   '高危') \
                          .replace('紧急风险', '紧急')
            self.buglist.append({
                'bugaddr'   : addr[0],
                'bugname'      : name[i],
                'bugrank'      : rank,
                'bugnumber'    : '|'.join([cve[i],cnvd[i],cnnvd[i]]),
                'bugdesc'      : self.raw_html(desc[i]),
                'bugplan'      : self.raw_html(plan[i]),
            })

    def handler_nsfocus_html(self):
        '''根据绿盟扫描器html格式漏洞报告进行转换'''
        data = str(self.content,encoding='utf-8')
        host = re.findall('<td>(.*?)</td>',data)[0]
        a = re.findall(r'''<tr class="(odd|even)" data-id=".*?" data-port="(.*?)" >([\s\S]*?)</table>''',data)
        for _,port,data in a:
            vuls = re.findall('''/><span class="level_danger_(.*?)" style="cursor:pointer">(.*?)</span>''',data)
            desc = ''.join(re.findall('''<th width="100">详细描述</th>([\s\S]*?)</tr>''',data))
            plan = ''.join(re.findall('''<th width="100">解决办法</th>([\s\S]*?)</tr>''',data))
            cve  = ''.join(re.findall(r'''http://cve.mitre.org/cgi-bin/cvename.cgi?name=(.*?)">''',data))
            cnnvd= ''.join(re.findall(r'''http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/(.*?)">''',data))
            cnvd = ''.join(re.findall(r'''http://www.cnvd.org.cn/flaw/show/(.*?)">''',data))
            rank = vuls[0][0].replace('high',   '高危') \
                             .replace('middle', '中危') \
                             .replace('low',    '低危')
            self.buglist.append({
                'bugaddr'   : '%s:%s'%(host,port),
                'bugname'      : vuls[0][1],
                'bugrank'      : rank,
                'bugnumber'    : '|'.join([cve,cnvd,cnnvd]),
                'bugdesc'      : self.raw_html(desc),
                'bugplan'      : self.raw_html(plan),
            })

    def handler_awvs_html(self):
        '''根据Awvs扫描器html格式Affected Items漏洞报告进行转换'''
        html = self.text
        starturl   = re.findall("Start url</td>.*?<td>(.*?)</td>",html,re.DOTALL)[0]
        addr = re.findall('//(.*?)/',starturl)[0]
        name = re.findall("<td><b>Alert group</b></td>.*?<td><b>(.*?)</b>",html,re.DOTALL)
        rank = re.findall("<td>Severity</td>.*?<td>(.*?)</td>",html,re.DOTALL)
        desc = re.findall("<td>Description</td>.*?<td>(.*?)</td>",html,re.DOTALL)
        plan = re.findall("<td>Recommendations</td>.*?<td>(.*?)</td>",html,re.DOTALL)

        for i in range(len(name)):
            rank = rank[i].replace('Low',   '低危') \
                          .replace('Medium','中危') \
                          .replace('High',  '高危') \
                          .replace('Crital','紧急')
            self.buglist.append({
                'bugaddr'      : addr,
                'bugname'      : name[i],
                'bugrank'      : rank,
                'bugnumber'    : '',
                'bugdesc'      : self.raw_html(desc[i]),
                'bugplan'      : self.raw_html(plan[i]),
            })
    def handler_awvs_html_developer(self):
        '''Developer Report'''
        html = self.text
        surl = re.findall("Start url</td>.*?<td>(.*?)</td>",html,re.DOTALL)[0]
        ip   = re.findall('//(.*?)/',surl)[0]
        rel = re.findall("\"ax-section-title ax-section-title--big\">.*?<img src=\"data:image/png;base64,.*?\">(.*?)</h3>.*?<td class=\"ax-alert-info__severity_value\">(.*?)</td>.*?<h4 class=\"ax-section-title\">.*?Description.*?</h4>.*?<p>(.*?)</p>.*?<h4 class=\"ax-section-title\">.*?Impact.*?</h4>.*?<p>(.*?)</p>.*?<h4 class=\"ax-section-title\">.*?Affected items.*?</h4>(.*?)<h3 class=",html,re.DOTALL)
        for name,rank,desc,plan,items in rel:
            reitem = re.findall("<b>(.*?)</b></td></tr>.*?<tr><td><code style=\"white-space: pre-line\">(.*?)</code></td></tr>",items,re.DOTALL)
            for addr,req in reitem:
                rank = rank.replace('Informational','低危').replace('Low','低危').replace('Medium','中危').replace('High','高危').replace('Crital','紧急')
                self.buglist.append({
                    'bugaddr'      : 'http://'+ip+req.split()[1],
                    'bugname'      : self.raw_html(name),
                    'bugrank'      : self.raw_html(rank),
                    'bugnumber'    : '',
                    'bugdesc'      : self.raw_html(desc),
                    'bugplan'      : self.raw_html(plan),
                    'bugreq'       : req
                })

    def handler_nessus_csv(self):
        '''根据Nessus扫描器csv格式漏洞报告进行转换'''
        i=0
        for row in csv.DictReader(self.steam):
            field[i] = row
            bug = {}
            bug['bugaddr']  = field[i]['Host']
            bug['bugname']  = field[i]['Name']
            bug['bugrank']  = field[i]['Risk'].replace('Low','低危') \
                                              .replace('Medium','中危') \
                                              .replace('High','高危') \
                                              .replace('Crital','紧急')
            bug['bugnumber']= field[i]['CVE']
            bug['bugdesc']  = field[i]['Description']
            bug['bugplan']  = field[i]['Solution']
            bug['bugnote']  = field[i]['See Also']
            self.buglist.append(bug)
            i += 1

    def handler_topsec_xls(self):
        '''根据天融信漏洞扫描器xls格式漏洞报告进行转换'''
        table = self.steam.sheets()[0]
        ip = table.row_values(1)[0]
        nrows = table.nrows

        for i in range(nrows):
            if i ==0:
               continue
            ip_temp = table.row_values(i)[1] \
                           .replace('低风险',  '低危') \
                           .replace('中风险',  '中危') \
                           .replace('高风险',  '高危') \
                           .replace('紧急风险','紧急')
            self.buglist.append({
                'bugaddr'   : table.row_values(i)[0],
                'bugname'   : table.row_values(i)[3],
                'bugrank'   : ip_temp,
                'bugdesc'   : table.row_values(i)[7],
                'bugplan'   : table.row_values(i)[8],
                'bugnote'   : table.row_values(i)[5]
            })

    def handler_nessus_html(self):
        '''根据Nessus扫描器html格式漏洞报告进行转换'''
        html = str(self.content,encoding='utf-8')
        detaillist = re.findall('<h2 xmlns="" class="classsection" .*?>(.*?)<h2 xmlns="" class="classsection" .*?>',html.replace('\n','').replace('\r\n',''),re.S)
        for d in detaillist:
            bugaddr = re.findall(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])',d)[0]
            bugs_raw = re.findall('Name</span></td></tr><tr>(.*?)</table>',d)
            for b in bugs_raw:
                ranks = re.findall('important;">(.*?)</span>',b)
                names = re.findall('normal;">(.*?)</span>',b)
                for i in range(len(ranks)):
                    if ranks[i] != "Info":
                        rank_single = ranks[i].replace('Low','低危') \
                                .replace('Medium','中危') \
                                .replace('High','高危') \
                                .replace('Crital','紧急').split()[0]

                        name_single = names[i]
                        self.buglist.append({
                            'bugaddr'   :bugaddr, #漏洞地址      （必须，可以是url地址或者某个IP地址对应端口如 http://127.0.0.1/bugaddr?id=1或 127.0.0.1:1433
                            'bugname'   :name_single, #漏洞名称      （必须
                            'bugrank'   :rank_single, #漏洞等级      （必须，分四个等级【紧急，高危，中危，低危】 如果不是这个名称要进行相应转换
                        })

    def handler_nessus_csv(self):
        '''根据Nessus扫描器csv格式漏洞报告进行转换'''
        with open(self.filepath) as f:
            for row in csv.reader(f):
                line = row
                bug = {}
                bug['bugaddr'] = line[4]
                bug['bugname'] = line[7]
                bug['bugrank'] = line[3].replace('Low','低危') \
                                        .replace('Medium','中危') \
                                        .replace('High','高危') \
                                        .replace('Crital','紧急')
                bug['bugnumber'] = line[1]
                bug['bugdesc'] = line[9]
                bug['bugplan'] = line[10]
                bug['bugnote'] = line[11]
                if bug['bugrank'] != "None":
                    self.buglist.append(bug)

