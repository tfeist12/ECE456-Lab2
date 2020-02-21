from helper import parseAddress, parsePort, getByteArray, ipSplitAdd, adder, ipConvert
import sys
import L1


# Test length of command line args for sender
def testArgs():
    if len(sys.argv) != 7:
        print("Must use 6 command line arguments for sender, Exiting!")
        sys.exit()


# Main method
if __name__ == '__main__':

    print("----------------------------------------------------------")
    testArgs()
    datafn, sip, dip, sSPort, sDPort, datagramfn = str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3]), str(
        sys.argv[4]), str(sys.argv[5]), str(sys.argv[6])

    # Parse and test ip addresses
    sipList = parseAddress(sip)
    dipList = parseAddress(dip)
    sip = bytearray(sipList)
    dip = bytearray(dipList)

    # Parse and test ports
    sPort = parsePort(sSPort)
    dPort = parsePort(sDPort)

    # Get data from file and pad if necessary
    f0 = L1.testFile(datafn)
    data = f0.read()
    f0.close()
    dataLen = L1.testSize(data)
    print("Data: " + str(data)[2:][:len(data)])
    pad = 0
    if len(data) % 2 != 0:
        pad = 1
        data = L1.pad(data)

    # Get key from file
    f1 = L1.testFile("key.txt")
    key = f1.read()
    f1.close()
    L1.testKey(key)
    key = key.decode("utf-8")
    print("Key: " + key + "\n")

    # Print info to user
    print("Data Filename: " + datafn)
    print("Source IP: " + str(ipConvert(sip)[0]) + " (LE10)")
    print("Destination IP: " + str(ipConvert(dip)[0]) + " (LE10)")
    print("Source Port: " + sSPort)
    print("Destination Port: " + sDPort)
    print("Datagram Filename: " + datagramfn + "\n")

    # Encrypt and convert to bytes
    chunks = L1.encrypt(data, key)
    bData = []
    for a in range(0, len(chunks)):
        for b in range(0, len(chunks[a])):
            bData.append(ord(chunks[a][b]))
    bData = bytearray(bData)

    # Write encrypted data
    L1.writeData("sOut", chunks, pad)

    # Get everything we nee to generate checksum
    siph, diph = ipSplitAdd(sip), ipSplitAdd(dip)
    zero, protocol = bytes([0]), bytes([17])
    totalLen = dataLen + 8  # Total length is the length in bytes of the datagram:the udp header and data before padding
    tl = getByteArray(totalLen)
    sp = getByteArray(int(sPort))
    dp = getByteArray(int(dPort))

    print("Filesize: " + str(dataLen) + " Bytes")
    print("Total Length: " + str(totalLen) + " Bytes")

    # Add everything up
    cs = adder(siph, diph)
    cs = adder(cs, zero)
    cs = adder(cs, protocol)
    cs = adder(cs, tl)
    cs = adder(cs, sp)
    cs = adder(cs, dp)
    cs = adder(cs, tl)

    # Add data
    for a in range(0, len(chunks)):
        x = chunks[a]
        y = bin(ord(x[0]))[2:].zfill(8) + bin(ord(x[1]))[2:].zfill(8)
        y = int(y, 2)
        cs = adder(cs, y)

    # take ones compliment
    cs = bytes.fromhex(hex(cs)[2:].zfill(4))
    x = int(cs.hex(), 16) ^ int(0xFFFF)
    cs = getByteArray(x)
    print("Checksum is: 0x" + cs.hex())

    # Generate pseudo header
    ph = sip + dip + zero + protocol + tl
    if len(ph) != 12:
        print("Size of pseudo header isn't 12 bytes, Exiting!")
        sys.exit()

    # Generate UDP Datagram
    udpdg = sp + dp + tl + cs + bData
    both = ph + udpdg

    # Write to datagram file
    file = open(datagramfn, "wb")
    file.write(both)
    file.close()
    print("Successfully wrote " + datafn + " to " + datagramfn)
    print("----------------------------------------------------------")
