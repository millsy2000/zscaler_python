"""
Written by Craig B.
https://github.com/Phatkone
           ,,,
          (. .)
-------ooO-(_)-Ooo-------
"""

import re

regexv4 = "^(\d{1,2}\.|[0-1][0-9][0-9]\.|2[0-4][0-9]\.|25[0-5]\.){3}(\d{1,2}|[0-1][0-9][0-9]|2[0-4][0-9]|25[0-5])(\/\d{1,2})?$"
regexv6 = "^[0-9a-f]{1,4}:[0-9a-f:]+(\/\d{1,3})?$"
regexfqdn = "^[A-Za-z0-9\-\.]+$"
regexwcfqdn = "^[A-Za-z0-9\-\.\*]+$"

def isIPv4(inAddr: str) -> bool:
    if re.match(regexv4, inAddr):
        return True
    else:
        return False


def isIPv6(inAddr: str) -> bool:
    if re.match(regexv6, inAddr):
        return True
    else:
        return False


def isFQDN(inAddr: str) -> bool:
    if re.match(regexfqdn, inAddr) and isIPv6(inAddr) == False and isIPv4(inAddr) == False:
        return True
    else:
        return False

def isFQDNWildcard(inAddr: str) -> bool:
    if re.match(regexwcfqdn, inAddr) and isIPv6(inAddr) == False and isIPv4(inAddr) == False and isFQDN(inAddr) == False:
        return True
    else:
        return False