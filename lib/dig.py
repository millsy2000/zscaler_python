"""
Written by Craig B.
https://github.com/Phatkone
           ,,,
          (. .)
-------ooO-(_)-Ooo-------
"""

import dns.name
import dns.message
import dns.query
import dns.flags
from lib.ipReg import isIPv4, isIPv6, isFQDN

def dig(fqdn: str, nameserver: str = '8.8.8.8') -> list:
    domain = dns.name.from_text(fqdn)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)
    rdata = dns.rdatatype.A
    request = dns.message.make_query(domain, rdata)
    request.flags |= dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, 65535, dns.rdatatype.OPT, create=True, force_unique=True)
    response = dns.query.udp(request, nameserver)
    entries = []
    if len(response.answer) < 1:
        return []
    for a in response.answer[0].items:
        entries.append(str(a))
    return entries


def getARecords(fqdn: str, dns_server: str = '8.8.8.8') -> list:
    records = dig(fqdn, dns_server)
    ret = []
    for record in records:
        if isIPv4(record) == False and isIPv6(record) == False and isFQDN(record) == True:
            r = getARecord(record, dns_server)
            if type(r) == list:
                for v in r:
                    if len(v) > 1:
                        ret.append(v)
            else:
                ret.append(r)
        elif isIPv4(record):
            ret.append(record)
    return ret


def getARecord(fqdn: str, dns_server: str = '8.8.8.8') -> str:
    while isIPv4(fqdn) == False:
        d = dig(fqdn, dns_server)
        if len(d) == 1:
            fqdn = d[0]
        elif len(d) > 1:
            for r in d:
                getARecord(r, dns_server)
        elif len(d) == 0:
            return 
    return fqdn