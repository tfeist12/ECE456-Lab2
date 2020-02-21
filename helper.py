from struct import unpack, pack
import binascii
import re
import sys


# Break IP Address down to byte array
def parseAddress(ip):
    out = re.findall(r'\d+', ip)
    for a in range(0, len(out)):
        if out[a].isdigit():
            if int(out[a]) <= 255:
                out[a] = int(out[a])
            else:
                print("Invalid ip address for input: Portion of address falls out of byte range, Exiting!")
                sys.exit()
        else:
            print("Invalid ip address for input: Non-numeric, Exiting!")
            sys.exit()
    if len(out) != 4:
        print("Invalid ip address for input: Must be 4 integers, Exiting!")
        sys.exit()
    return out


# Convert IP to little endian notation
def ipConvert(ip):
    ipn = bytes(ip)
    lEndian = unpack('<I', ipn)
    out = [lEndian[0], hex(lEndian[0])]
    return out


# Split 32bit ip address into two 16bit chunks and add them
def ipSplitAdd(ip):
    half1 = bytearray(2)
    half2 = bytearray(2)
    half1[0], half1[1] = ip[0], ip[1]
    half2[0], half2[1] = ip[2], ip[3]
    h1 = binascii.hexlify(half1)
    h2 = binascii.hexlify(half2)
    add = int(h1, 16) + int(h2, 16)
    add = outCarry(add)
    return add


# Check for carry out 1 and add it back in at LSB position
def outCarry(add):
    while len(hex(add)[2:]) == 5:
        add = int(hex(add)[3:], 16) + int(hex(add)[2:][0], 16)
    return add


# Break port down to byte
def parsePort(port):
    out = re.findall(r'\d+', port)
    if len(out) != 1:
        print("Invalid port for input, Exiting!")
        sys.exit()
    else:
        if int(out[0]) > 65535:
            print("Invalid port for input: Port falls out of two byte range, Exiting!")
            sys.exit()
        else:
            out = out[0]
    return out


# Return 16bit byte array from input
def getByteArray(size):
    # if size > 15:
    a = hex(size)[2:].zfill(4)
    x = bytearray.fromhex(a)
    return x


def adder(x, y):
    if isinstance(x, type(b'\x00')) | isinstance(x, type(bytearray(1))):
        x = binascii.hexlify(x)
        x = int(x, 16)

    if isinstance(y, type(b'\x00')) | isinstance(y, type(bytearray(1))):
        y = binascii.hexlify(y)
        y = int(y, 16)

    add = int(hex(x)[2:], 16) + int(hex(y)[2:], 16)
    add = outCarry(add)
    return add
