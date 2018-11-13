#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import re
import socket
import os
import struct
import array
import time
from threading import Thread
from core.util import CoroutinePool,gethosts,getports
from core.log import logging


PORTS = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144," \
        "146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458," \
        "464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687," \
        "691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990," \
        "992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138," \
        "1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218," \
        "1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417," \
        "1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688," \
        "1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972," \
        "1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107," \
        "2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383," \
        "2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725," \
        "2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3050," \
        "3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372," \
        "3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814," \
        "3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111," \
        "4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009," \
        "5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280," \
        "5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730," \
        "5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952," \
        "5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547," \
        "6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881-6890,6901,6969,7000-7002,7004,7007,7019," \
        "7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921," \
        "7937-7938,7999-8999,20880," \
        "9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485," \
        "9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9943-9944,9968,9998-10004,10009-10010,10012," \
        "10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174," \
        "12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016," \
        "16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005," \
        "20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201," \
        "30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443," \
        "44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103," \
        "51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"

SIGNS = (
    #协议 | 版本 | 关键字
    b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
    b"xmpp|xmpp|^\<\?xml version='1.0'\?\>",

    b'netbios|netbios|^\x79\x08.*BROWSE',
    b'netbios|netbios|^\x79\x08.\x00\x00\x00\x00',
    b'netbios|netbios|^\x05\x00\x0d\x03',
    b'netbios|netbios|^\x82\x00\x00\x00',
    b'netbios|netbios|\x83\x00\x00\x01\x8f',

    b'backdoor|backdoor|^500 Not Loged in',
    b'backdoor|backdoor|GET: command',
    b'backdoor|backdoor|sh: GET:',
    b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
    b'backdoor|backdoor|^bash[$#]',
    b'backdoor|backdoor|^sh[$#]',
    b'backdoor|backdoor|^Microsoft Windows',
    b'db2|db2|.*SQLDB2RA',
    b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
    b'finger|finger|^\r\n	Line	  User',
    b'finger|finger|Line	 User',
    b'finger|finger|Login name: ',
    b'finger|finger|Login.*Name.*TTY.*Idle',
    b'finger|finger|^No one logged on',
    b'finger|finger|^\r\nWelcome',
    b'finger|finger|^finger:',
    b'finger|finger|^must provide username',
    b'finger|finger|finger: GET: ',
    b'ftp|ftp|^220.*\n331',
    b'ftp|ftp|^220.*\n530',
    b'ftp|ftp|^220.*FTP',
    b'ftp|ftp|^220 .* Microsoft .* FTP',
    b'ftp|ftp|^220 Inactivity timer',
    b'ftp|ftp|^220 .* UserGate',
    b'ftp|ftp|^220.*FileZilla Server',

    b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61',
    b'ldap|ldap|^\x30\x32\x02\x01',
    b'ldap|ldap|^\x30\x33\x02\x01',
    b'ldap|ldap|^\x30\x38\x02\x01',
    b'ldap|ldap|^\x30\x84',
    b'ldap|ldap|^\x30\x45',

    b'ldp|ldp|^\x00\x01\x00.*?\r\n\r\n$',

    b'rdp|rdp|^\x03\x00\x00\x0b',
    b'rdp|rdp|^\x03\x00\x00\x11',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    b'rdp|rdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    b'rdp|rdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    b'rdp|rdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    b'rdp-proxy|rdp-proxy|^nmproxy: Procotol byte is not 8\n$',

    b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    b'msrpc|msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    b'mssql|mssql|^\x05\x6e\x00',
    b'mssql|mssql|^\x04\x01',
    b'mssql|mysql|;MSSQLSERVER;',

    b'mysql|mysql|mysql_native_password',
    b'mysql|mysql|^\x19\x00\x00\x00\x0a',
    b'mysql|mysql|^\x2c\x00\x00\x00\x0a',
    b'mysql|mysql|hhost \'',
    b'mysql|mysql|khost \'',
    b'mysql|mysql|mysqladmin',
    b'mysql|mysql|whost \'',
    b'mysql|mysql|^[.*]\x00\x00\x00\n.*?\x00',
    b'mysql-secured|mysql|this MySQL server',
    b'mysql-secured|MariaDB|MariaDB server',
    b'mysql-secured|mysql-secured|\x00\x00\x00\xffj\x04Host',

    b'db2jds|db2jds|^N\x00',

    b'nagiosd|nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    b'nessus|nessus|< NTP 1.2 >\x0aUser:',
    b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
    b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
    b'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    b'oracle-https|^220- ora',
    b'rmi|rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
    b'rmi|rmi|^\x4e\x00\x09',
    b'postgresql|postgres|Invalid packet length',
    b'postgresql|postgres|^EFATAL',

    b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    b'rpc|rpc|\x01\x86\xa0',
    b'rpc|rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
    b'rpc|rpc|^\x80\x00\x00',
    b'rsync|rsync|^@RSYNCD:',
    b'smux|smux|^\x41\x01\x02\x00',
    b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    b'snmp|snmp|\x41\x01\x02',
    b'socks|socks|^\x05[\x00-\x08]\x00',
    b'ssl|ssl|^..\x04\0.\0\x02',
    b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
    b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
    b'ssl|ssl|SSL.*GET_CLIENT_HELLO',
    b'ssl|ssl|^-ERR .*tls_start_servertls',
    b'ssl|ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
    b'ssl|ssl|^\x16\x03\0..\x02\0\0F\x03\0',
    b'ssl|ssl|^\x15\x03\0\0\x02\x02\.*',
    b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
    b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
    b'sybase|sybase|^\x04\x01\x00',

    b'telnet|telnet|Telnet',
    b'telnet|telnet|^\xff[\xfa-\xff]',
    b'telnet|telnet|^\r\n%connection closed by remote host!\x00$',

    b'rlogin|rlogin|login: ',
    b'rlogin|rlogin|rlogind: ',
    b'rlogin|rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',

    b'tftp|tftp|^\x00[\x03\x05]\x00',
    b'uucp|uucp|^login: password: ',
    b'vnc|vnc|^RFB',

    b'imap|imap|^\* OK.*?IMAP',
    b'pop|pop|^\+OK.*?',
    b'smtp|smtp|^220.*?SMTP',
    b'smtp|smtp|^554 SMTP',
    b'ftp|ftp|^220-',
    b'ftp|ftp|^220.*?FTP',
    b'ftp|ftp|^220.*?FileZilla',

    b'ssh|ssh|^SSH-',
    b'ssh|ssh|connection refused by remote host.',

    b'rtsp|rtsp|^RTSP/',
    b'sip|sip|^SIP/',
    b'nntp|nntp|^200 NNTP',
    b'sccp|sccp|^\x01\x00\x00\x00$',

    b'webmin|webmin|.*MiniServ',
    b'webmin|webmin|^0\.0\.0\.0:.*:[0-9]',
    b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',

    b'smb|smb|^\x83\x00\x00\x01\x8f',
    b'mongodb|mongodb|MongoDB',

    b'rsync|rsync|@RSYNCD:',
    b'mssql|mssql|MSSQLSERVER',

    b'vmware|vmware|VMware',

    b'redis|redis|^-ERR unknown command',
    b'redis|redis|^-ERR wrong number of arguments',
    b'redis|redis|^-DENIED Redis is running',

    b'memcached|memcached|^ERROR\r\n',

    b'websocket|websocket|^HTTP.*?websocket',

    b'http|http|^HTTP/',
    b'http|https|^\<!DOCTYPE HTML PUBLIC',
    b'http|topsec|^\x15\x03\x03\x00\x02\x02',   #天融信网站安全监控系统

    b'svn|svn|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'dubbo|dubbo|^Unsupported command',
)

SERV = {
    '21'    :'ftp',
    '22'    :'ssh',
    '23'    :'telnet',
    '25'    :'smtp',
    '53'    :'dns',
    '80'    :'http',
    '110'   :'pop',
    '135'   :'ntebios',
    '139'   :'ntebios',
    '161'   :'snmp',
    '389'   :'ldap',
    '443'   :'https',
    '445'   :'smb',
    '873'   :'rsync',
    '1080'  :'socks',
    '3389'  :'rdp',
    '3306'  :'mysql',
    '3690'  :'svn',
    '1433'  :'mssql',
    '1521'  :'oracle',
    '5432'  :'postgresql',
    '6379'  :'redis',
    '8080'  :'http',
    '11211' :'memcached',
    '27017' :'mongodb',
    '2181'  :'zookeeper',
    '50000' :'db2',
}
#开多线程时monkey会阻塞住线程的继续执行，需要对monkey.patch_all进行处理
#https://stackoverflow.com/questions/9192539/using-gevent-monkey-patching-with-threading-makes-thread-work-serially

class SendPingThr(Thread):
    def __init__(self, iplist, icmpPacket, icmpSocket, timeout=5):
        Thread.__init__(self)
        self.sock = icmpSocket
        self.iplist = iplist
        self.packet = icmpPacket
        self.timeout = timeout
        self.sock.settimeout(timeout + 3 )

    def run(self):
        time.sleep(1)  #等待接收线程启动
        for ip in self.iplist:
            try:
                self.sock.sendto(self.packet, (ip, 0))
            except socket.timeout:
                break
        time.sleep(1) #等待接收线程完成

class Nscan(object):
    def __init__(self, timeout=5, IPv6=False):
        self.timeout = timeout
        self.IPv6 = IPv6
        self.__data = struct.pack('d', time.time())   #用于ICMP报文的负荷字节（8bit）
        self.__id = os.getpid()   #构造ICMP报文的ID字段，无实际意义

    @property
    def __icmpSocket(self):
        '''创建ICMP Socket'''
        if not self.IPv6:
            Sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        else:
            Sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))
        return Sock

    def __inCksum(self, packet):
        '''ICMP 报文效验和计算方法'''
        if len(packet) & 1:
            packet = packet + '\\0'
        words = array.array('h', packet)
        sum = 0
        for word in words:
            sum += (word & 0xffff)
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        return (~sum) & 0xffff

    @property
    def __icmpPacket(self):
        '''构造 ICMP 报文'''
        if not self.IPv6:
            header = struct.pack('bbHHh', 8, 0, 0, self.__id, 0) # TYPE、CODE、CHKSUM、ID、SEQ
        else:
            header = struct.pack('BbHHh', 128, 0, 0, self.__id, 0)

        packet = header + self.__data   # packet without checksum
        chkSum = self.__inCksum(packet) # make checksum

        if not self.IPv6:
            header = struct.pack('bbHHh', 8, 0, chkSum, self.__id, 0)
        else:
            header = struct.pack('BbHHh', 128, 0, chkSum, self.__id, 0)
        return header + self.__data   # packet *with* checksum

    def isUnIP(self, IP):
        '''判断IP是否是一个合法的单播地址'''
        IP = [int(x) for x in IP.split('.') if x.isdigit()]
        if len(IP) == 4:
            if (0 < IP[0] < 223 and IP[0] != 127 and IP[1] < 256 and IP[2] < 256 and 0 < IP[3] < 255):
                return True
        return False

    def ping(self, iplist):
        sock = self.__icmpSocket
        sock.settimeout(self.timeout)
        packet = self.__icmpPacket
        recvFroms = set()   #接收线程的来源IP地址容器
        iplist = {ip for ip in iplist if self.isUnIP(ip)}
        sendThr = SendPingThr(iplist, packet, sock, self.timeout)
        sendThr.start()
        while True:
            logging.load('recv %s'%time.time())
            try:
                recvFroms.add(sock.recvfrom(255)[1][0])
            except Exception as e:
                pass#sleep(0.001)#print('ping',e)
            finally:
                if not sendThr.isAlive():
                    break
        return recvFroms & iplist

class PortScan(object):
    def __init__(self,hosts,ports=None,neping=None,threads=None,timeout=None):
        self.hosts = gethosts(hosts)
        self.ports = getports(ports) if ports else getports(PORTS)
        self.neping = neping and True
        self.threads = threads or 100
        self.timeout = timeout or 10
        self.result = {}

    def scan(self):
        hosts = self.ping(self.hosts) if self.neping else self.hosts
        pool = CoroutinePool(self.threads)
        for host in hosts:
            for port in self.ports:
                pool.spawn(self.addret,host,port)
        pool.join()
        return self.result

    def ping(self,hosts):
        return list(Nscan().ping(set(hosts)))

    def port(self,host,port):
        logging.load('[scan %s - %s    ]'%(host,port))
        isopen = False
        data = b''
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((host,int(port)))
            isopen = True
        except Exception as e:# socket.timeout ConnectionRefusedError
            pass#print('1',e)
            s.close()
            return isopen,data
        try:
            data = s.recv(256)
            return isopen,data
        except Exception as e:
            pass#print('2',e)
        try:
            a = ('GET / HTTP/1.1\r\nHOST: %s\r\n\r\n'%host)
            s.sendall(a.encode())
            data = s.recv(256)
            return isopen,data
            #print(data.decode('gbk','ignore'))
        except Exception as e:
            pass#print('3',e)
        finally:
            s.close()   #关闭连接
            return isopen,data

    def addret(self,host,port):
        isopen,data = self.port(host,port)
        protocol = 'unknow'
        softver = 'unknow'
        if data:
            for s in SIGNS:
                try:
                    s = s.split(b'|')
                    if re.search(s[-1],data,re.IGNORECASE):
                        protocol = s[0].decode()
                        softver =  s[1].decode()
                        break
                except Exception as e:
                    print(e,s[-1],host,port,data)
            if protocol == 'unknow' and str(port) in SERV.keys():
                protocol = SERV[str(port)]
        if isopen:
            if host not in self.result:
                self.result[host] = {}
                self.result[host]['hostname']   = ''
                self.result[host]['mac']        = ''
                self.result[host]['status']     = 'up'
                self.result[host]['ostype']     = ''
                self.result[host]['ports']      = set()
            self.result[host]['ports'].add((
                host,
                port,
                'tcp',
                'open',
                protocol,
                '',
                '',
                softver,
                data))

if __name__=='__main__':
    s=PortScan('59.41.129.37',neping=0)
    for h,v in s.scan():
        print(h)
        for p in v['ports']:
            print('    ',p[1],p[2],p[4])