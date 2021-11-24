"""
Written by Craig B.
https://github.com/Phatkone
           ,,,
          (. .)
-------ooO-(_)-Ooo-------
"""

import struct
import socket
import lib.ipReg as ipReg

def cidr2subnet(cidr: str) -> str:
    bits = {
        0:0,
        1:128,
        2:192,
        3:224,
        4:240,
        5:248,
        6:252,
        7:254,
        8:255
    }
    if len(cidr) > 3 and '/' in cidr:
        cidr = cidr.split('/')[1]
    if '/' in cidr:
        cidr = cidr.replace('/',"")
    cidr = int(cidr)
    if cidr <= 8:
        return "{}.0.0.0".format(bits[cidr])
    if cidr > 8 and cidr <= 16:
        return "255.{}.0.0".format(bits[cidr-8])
    if cidr > 16 and cidr <= 24:
        return "255.255.{}.0".format(bits[cidr-16])
    if cidr > 24 and cidr <= 32:
        return "255.255.255.{}".format(bits[cidr-24])
    else:
        return "Invalid CIDR '{}'".format(cidr)

def subnet2cidr(mask: str) -> str:
    bits = {
        0:0,
        128:1,
        192:2,
        224:3,
        240:4,
        248:5,
        252:6,
        254:7,
        255:8
    }
    if ipReg.isIPv4(mask) == False or '/' in mask or len(mask) > 15 or len(mask) < 7:
        return "Invalid netmask '{}'".format(mask)
    octets = []
    for octet in mask.split("."):
        octets.append(int(octet))
    try:
        if '255.255.255.' in mask:
            #/24 - 32
            return bits[octets[3]]+24
        elif '255.255.' in mask and '.0' in mask:
            #/16 - /23
            return bits[octets[2]]+16
        elif '255.' in mask and '.0.0' in mask:
            #/8 - /15
            return bits[octets[1]]+8
        elif '.0.0.0' in mask:
            #/0 - /7
            return bits[octets[0]]
        else:
            return "Invalid Mask '{}'".format(mask)
    except KeyError:
        return "Invalid Mask '{}'".format(mask)


def ip2int(addr: str) -> int:
    if '/' in addr:
        addr = addr.split('/')[0]
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", addr))

def mask2range(subnet: str) -> str:
    if ipReg.isIPv4(subnet):
        if '/' in subnet:
            cidr = int(subnet.split('/')[1])
        elif len(subnet) <= 15 and len(subnet) >= 7:
            cidr = subnet2cidr(subnet)
        if type(cidr) == str:
            return "Invalid Subnet'{}'".format(subnet)
    elif (len(subnet) <= 3 and '/' in subnet) or (len(subnet) <= 2 and int(subnet) < 33):
        #cidr
        cidr = int(subnet.replace('/',""))
    else:
        return "Invalid Subnet '{}'".format(subnet)
    inverse = abs(cidr-32)
    return pow(2,inverse)-1