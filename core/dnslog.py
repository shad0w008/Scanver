#!/usr/bin/env python
# encoding=utf-8
#codeby     道长且阻
#email      @ydhcui/QQ664284092


import settings
import random


class DnslogService(object):
    def __init__(self,dnsserver):
        self.dnsserver = dnsserver

    def randomstr(self,len=32):
        str1 = ""
        for i in range(len):
            str1 += (random.choice("ABCDEF1234567890"))
        return str(str1)

    def getdns(self):
        self.randstr = self.randomstr()
        self.randstr

class ZoneResolver(BaseResolver):
    from dnslib import RR, QTYPE, RCODE
    from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger


    def __init__(self, zone, glob=False):
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr) for rr in RR.fromZone(zone)]
        self.glob = glob
        self.eq = 'matchGlob' if glob else '__eq__'

    def resolve(self, request, handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        for name, rtype, rr in self.zone:
            # Check if label & type match
            if getattr(qname, self.eq)(name) and (
                    qtype == rtype or qtype == 'ANY' or rtype == 'CNAME'):
                # If we have a glob match fix reply label
                if self.glob:
                    a = copy.copy(rr)
                    a.rname = qname
                    reply.add_answer(a)
                else:
                    reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME', 'NS', 'MX', 'PTR']:
                    for a_name, a_rtype, a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A', 'AAAA']:
                            reply.add_ar(a_rr)
        if not reply.rr:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def main():
    zone = '''
*.{dnsdomain}.       IN      NS      {ns1domain}.
*.{dnsdomain}.       IN      NS      {ns2domain}.
*.{dnsdomain}.       IN      A       {serverip}
{dnsdomain}.       IN      A       {serverip}
'''.format(
        dnsdomain=settings.DNS_DOMAIN, ns1domain=settings.NS1_DOMAIN,
        ns2domain=settings.NS2_DOMAIN, serverip=settings.SERVER_IP)
    resolver = ZoneResolver(zone, True)
    logger = MysqlLogger()
    print("Starting Zone Resolver (%s:%d) [%s]" % ("*", 53, "UDP"))

    udp_server = DNSServer(resolver,
                           port=53,
                           address='',
                           logger=logger)
    udp_server.start()
        
