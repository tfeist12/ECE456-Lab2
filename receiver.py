from helper import parseAddress, adder, ipConvert
import sys
import L1


# Test length of command line args for receiver
def testArgs():
    if len(sys.argv) != 4:
        print("Must use 3 command line arguments for receiver, Exiting!")
        sys.exit()


# Main method
if __name__ == '__main__':

    print("----------------------------------------------------------")
    testArgs()
    sip, dip, dgfn = str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3])

    # Parse and test ip addresses
    sip = parseAddress(sip)
    dip = parseAddress(dip)

    # Get data from datagram
    f0 = L1.testFile(dgfn)
    data = f0.read()
    f0.close()

    # Get key from file
    f1 = L1.testFile("key.txt")
    key = f1.read()
    f1.close()
    L1.testKey(key)
    key = key.decode("utf-8")

    # Checksum received with datagram
    rCS = int(hex(data[18])[2:] + hex(data[19])[2:], 16)

    # Calculate checksum manually using datagram and see if it matches
    cCS = 0x0
    for a in range(0, len(data), 2):
        if a != 18:
            x = hex(data[a])[2:].zfill(2)
            y = hex(data[a+1])[2:].zfill(2)
            cCS = adder(cCS, int(x+y, 16))

    # Calculate file length
    fl = int(hex(data[16])[2:] + hex(data[17])[2:], 16) - 8

    # Check that calculated and received checksums are the same
    if rCS + cCS != 0xFFFF:
        print("Received checksum differs from calculated checksum: Checksum Error!")
        sys.exit()
    else:
        ba = bytearray(len(data) - 20)
        count = 0
        for a in range(20, len(data)):
            ba[count] = data[a]
            count += 1
        chunks = L1.encrypt(ba, key)

        pad = 0
        tl = len(data) - 12
        if fl < len(chunks) * 2:
            pad = 1
            tl -= 1

        # Print info to user
        print("Source IP: " + str(ipConvert(sip)[1])[2:] + " (LE16)")
        print("Destination IP: " + str(ipConvert(dip)[1])[2:] + " (LE16)")
        print("Datagram Filename: " + dgfn + "\n")
        print("Filesize: " + str(fl) + " Bytes")
        print("Total Length: " + str(tl) + " Bytes")
        print("Checksum: " + str(hex(rCS)))
        print("Received checksum is the same as calculated checksum, Yay!")

        # Write decrypted data to a file
        L1.writeData("rOut", chunks, pad)
        print("Successfully decrypted " + dgfn + " to rOut")
        print("----------------------------------------------------------")



