import sys
from pip._vendor.distlib.compat import raw_input


# Divide data into 16 bit chunks
def divData(data):
    chunks = []
    for a in range(0, int(len(data) / 2)):
        s = ""
        for b in range(a * 2, (a + 1) * 2):
            s += chr(data[b])
        chunks.append(s)
    return chunks


# Divide key into single characters
def divKey(key):
    chunks = []
    for a in range(0, int(len(key.encode('utf-8')))):
        s = ""
        s += key[a]
        chunks.append(s)
    return chunks


# Split 16bit data chunks in half
def half(data):
    ha = []
    x = ord(data[:len(data) // 2])
    ha.append(x)
    y = ord(data[len(data) // 2:])
    ha.append(y)
    return ha


# Perform 8 iterations per chunk
def iteration(a, b, chunks, kBytes):
    ha = half(chunks[a])
    left, right = ha[0], ha[1]
    # print(str(ha[0]) + "," + str(ha[1]))
    xor = left ^ int(kBytes[b])
    # convert back to ascii and concatenate
    new = chr(ha[1]) + chr(xor)
    chunks[a] = new
    return chunks


# Write output data to file
def writeData(fn, chunks, pad):
    # Iterate through the list and write bytes to a file
    file = open(fn, "wb")
    for a in range(0, len(chunks)):
        x = chunks[a]
        for b in range(0, len(x)):
            by = bytes(x[b], 'utf-8')
            ab = a == len(chunks)-1
            cd = b == len(x)-1
            ef = pad == 1
            if not ab & cd & ef:
                file.write(by)
    file.close()


def encrypt(data, key):
    # Need to break up input data into 16bits chunks
    chunks = divData(data)

    # Break up key into bytes
    kBytes = divKey(key)
    for a in range(0, len(kBytes)):
        kBytes[a] = ord(kBytes[a])

    # Must iterate for number of 16bit chunks in the data
    for a in range(0, len(chunks)):
        # Eight iterations for encryption
        for b in range(0, 8):
            chunks = iteration(a, b, chunks, kBytes)

    return chunks


# Check if file exists and open if so
def testFile(filename):
    try:
        f0 = open(filename, "rb")
    except FileNotFoundError:
        print("File does not exist! Exiting!")
        sys.exit()
    return f0


# Ensure key is only 8 characters long
def testKey(key):
    if len(key) != 8:
        print("Key must be 8 characters long, Exiting!")
        sys.exit()


# Ensure number of bytes of data isn't 0
def testSize(data):
    if len(data) == 0:
        print("No data in the file, Exiting!")
        sys.exit()
    size = len(data)
    return size


# Pad the data if it isn't divisible by 16 bits
def pad(data):
    while len(data) % 2 != 0:
        data += b'\x00'
    return data
