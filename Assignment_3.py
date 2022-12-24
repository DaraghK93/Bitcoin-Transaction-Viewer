import hashlib
import struct
import time
import random
import socket
import datetime

## change to IP of system that's running it
myIP = '109.78.23.224'
myPort = 8080

## if this IP doesn't work, will need to find an online bitcoin node
peerIP = "188.68.53.44"
peerPort = 8333


def double_sha256(data):
    """ double hash a string to send as a message 

    Args:
        data (string): string you need to encrypt

    Returns:
        string: double  hashed string
    """
    m = hashlib.sha256(data)
    m = hashlib.sha256(m.digest())
    return m.digest()


def decode(message):
    """decode the message and get the constituent parts in a list

    Args:
        message (string): coded message

    Returns:
        string: decoded string
    """
    magic = struct.unpack('<I', message[0:4])[0]
    command = message[4:16].decode('utf-8').replace('\0', '')
    length = struct.unpack('<I', message[16:20])[0]
    checksum = struct.unpack('<I', message[20:24])[0]
    payload = message[24:]
    # return list of message parts
    y = [magic,command,length,checksum,payload]
    return y


def varint(msg):
    """function for handling variable integers
       if first byte is less than 253, take that as 
       the value and start the next part after that byte
       otherwise take the starting byte as below

    Args:
        msg (bytestring): start of the message

    Returns:
        ints: two ints, start and count, showing where to start the message
        and the count of chars that comes after
    """
    firstbyte = struct.unpack('<B', msg[0:1])[0]
    if firstbyte < 253:
        count = firstbyte
        start = 1
    elif firstbyte == 253:
        count = struct.unpack('<H',msg[1:3])[0]
        start = 3
    elif firstbyte == 254:
        count = struct.unpack('<I',msg[1:5])[0]
        start = 5
    else:
        count = struct.unpack('<Q',msg[1:9])[0]
        start = 9

    return start, count


def invparse(msg):
    """parse inv message to get the inv vectors

    Args:
        msg (bytestring): message

    Returns:
        ints: same as above for inventory vectors 
    """
    start,count = varint(msg)
    return msg[start:], count


# parse the inv vectors
def invvectparse(msg):
    """parse the inv vectors

    Args:
        msg (bytestring): coded message

    Returns:
        dictionary: dictionary containing all inventory vectors
    """
    # get the starting point of the vectors from the inv message
    vectors, countvectors = invparse(msg)
    # initialise empty dictionary to add the vectors to
    invdic = dict()
    vdict = dict()
    invdic["count"] = countvectors
    invdic["vectdic"] = vdict
    # loop through the amount of vectors in the payload,
    # each is 36 bytes so add 36 bytes to starting point each time
    for i in range(0, countvectors):
        typev = struct.unpack('<I', vectors[(36*i):(36*i)+4])[0]
        hashv = vectors[(36*i)+4:(36*i)+36]
        # only add if they are type 1 or 2
        # 1 is a transaction, 2 is a blcok
        if typev == 1 or typev == 2:
            typevname = "type"+str(i)
            hashname = "hash"+str(i)
            vdict[typevname] = typev
            vdict[hashname] = hashv
    # only return the dictionary if it is not empty, ie only if it contains tx or blocks
    if len(vdict) != 0:
        return invdic
    else:
        return


def parsetx(txpay):
    """parse the transaction payload

    Args:
        txpay (bytestring): paylod of transaction message

    Returns:
        list: list of all parts of the txopayload to be printed
    """
    # get version and parse
    version = struct.unpack('<I', txpay[0:4])[0]
    # flag, if 0 start here, if 1, skip 2
    flag = struct.unpack('>H', txpay[4:6])[0]
    if flag == 1:
        skip = 2
    else:
        skip = 0
    # txincount, get varint and start there
    tx_in_count = txpay[skip+4:]
    start, count = varint(tx_in_count)
    # txin, start from start point above and initialise empty dictionary
    txin = tx_in_count[start:]
    txindic = dict()

    # loop through the count and add hash and index to dictionary
    outpointstart = 0
    for i in range(0,count):
        # outpoint - always 36 bytes with hash and index
        outpoint = txin[outpointstart:outpointstart+36]
        txindic['outhash{}'.format(i)] = outpoint[0:32]
        txindic['outindex{}'.format(i)] = struct.unpack('<I', outpoint[32:36])[0]
        # add scriptlen and the starting point to the index each time
        # length of script with be varint so this will change each time
        script_length_start, script_length = varint(txin[outpointstart+36:])
        txindic['sigscript{}'.format(i)] = txin[outpointstart+36+script_length_start:outpointstart+36+script_length_start+script_length]
        txindic['sequence{}'.format(i)] = struct.unpack('<I', txin[outpointstart+36+script_length_start+script_length:outpointstart+40+script_length_start+script_length])[0]
        # add where it ended to the start point after every iteration
        outpointstart += 40+script_length_start+script_length

    # txout count, get varint, start there
    txoutc = txin[outpointstart:]
    txoutstart,txoutcount = varint(txoutc)
    txout = txoutc[txoutstart:]

    # txout, loop through count and add to dictionary
    # script lenght is varint so this will change the startpoint each time
    txoutdic = dict()
    startpoint = 0
    for i in range(0,txoutcount):
        txoutdic['txval{}'.format(i)] = struct.unpack('<Q', txout[startpoint:startpoint + 8])[0]
        outscriptlen = txout[startpoint + 8:]
        scriptstart, scriptlen = varint(outscriptlen)
        txoutdic['outscript{}'.format(i)] = txout[startpoint+8+scriptstart:startpoint+8+scriptstart+scriptlen]
        # add where it ended to the start point after every iteration
        startpoint += 8+scriptstart+scriptlen
    locktime = struct.unpack('<I', txout[startpoint:startpoint+4])[0]
    return [version,count,txindic,txoutcount,txoutdic,locktime]


def printTx(msg):
    """function to print the transactions as they come in

    Args:
        msg (list): list of all the parts of tx that need to be printed
    """
    print("-"*14)
    print("Transaction")
    version = msg[0]
    print("Version:", version)
    incount = msg[1]
    print("No. of Inputs:",incount)
    txindic = msg[2]
    # loop through count and print
    for i in range(0,incount):
        print("Previous Hash:", txindic['outhash'+str(i)])
    outcount = msg[3]
    print("No. of Outputs:",outcount)
    outdic = msg[4]
    # loop through count and print
    for j in range(0,outcount):
        print("Value of Output " + str(j+1)+":",outdic['txval'+str(j)])
    time = msg[5]
    # time could mean transaction is not locked, transaction will be unlocked at a certain block
    # or the time when the transaction will be unlocked
    if time == 0:
        print("Transaction not Locked")
    elif time < 500000000:
        print("Transaction Unlocked at Block",time)
    else:
        propertime = datetime.datetime.fromtimestamp(time)
        print(f"{propertime:%d/%m/%Y %H:%M:%S}")
    return


def parseblock(blockpay):
    """parse the block messages
       always the same length
       return parts in a list

    Args:
        blockpay (bytestring): payload of block to be printed

    Returns:
        list: list of all block messages to be printed
    """
    version = struct.unpack('<I', blockpay[0:4])[0]
    prevblock = struct.unpack('<32s', blockpay[4:36])[0]
    merkleroot = struct.unpack('<32s', blockpay[36:68])[0]
    timestamp = struct.unpack('<I', blockpay[68:72])[0]
    bits = struct.unpack('<I', blockpay[72:76])[0]
    nonce = struct.unpack('<I', blockpay[76:80])[0]
    txncountpoint = blockpay[80:]
    txncountstart,txncount = varint(txncountpoint)
    return [version,prevblock,timestamp,nonce,txncount,merkleroot,bits]


def printBlock(msg):
    """print the block to the command line

    Args:
        msg (list): block messages to print
    """
    version = msg[0]
    prevblock = msg[1]
    timestamp = msg[2]
    propertime = datetime.datetime.fromtimestamp(timestamp)
    nonce = msg[3]
    txncount = msg[4]
    print("-"*14)
    print("Block")
    print("Version:",version)
    print("Previous Block Hash:",prevblock)
    print("Time Block Created:",f"{propertime:%d/%m/%Y %H:%M:%S}")
    print("Nonce:",nonce)
    print("No. of Transactions:",txncount)
    print("")
    return


def createversionPayload():
    """create version message payload to send to node to connect
       must pack all into byte string values

    Returns:
        bytstring: bytstring that is sent to peer node
    """
    version = struct.pack("<i", 70015)
    services = struct.pack("<Q",0)
    now = int(time.time())
    timestamp = struct.pack('<q', now)
    addrrecserv = services
    # must convert IPV4 IP to IPv6, ad 12 bytes at beginning
    addrecIP = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + socket.inet_aton(myIP)
    addrecport = struct.pack('<H', myPort)
    addrfrom = b'\x00'*26
    nonce = struct.pack('<Q',random.randint(0, 9))
    user_agent = b'\x00'
    start_height = b'\x00'*4
    relay = struct.pack('<?', 1)
    # concatenate all into byte string
    return version + services +timestamp + addrrecserv + addrecIP + addrecport + addrfrom + nonce + user_agent + \
           start_height + relay


def createversionmsg():
    """create the header for the version message and concatenate with payload from above

    Returns:
        bytestring: header and version message to send
    """
    magic = b'\xf9\xbe\xb4\xd9'
    command = "version".encode('utf-8') + b'\x00'*5
    payload = createversionPayload()
    checksum = double_sha256(payload)[0:4]
    length = struct.pack('<I',len(payload))
    return magic + command + length + checksum + payload


def createverack():
    """create verack (version acknowledgement message)
       create header and send empty bytes as the payload and concatenate

    Returns:
        bytestring: header and verack to send to node
    """
    magic = b'\xf9\xbe\xb4\xd9'
    command = "verack".encode('utf-8') + b'\x00'*6
    checksum = double_sha256(b'')[0:4]
    payload = b''
    length = struct.pack('<I', len(payload))
    return magic + command + length + checksum + payload


def createVarInt(count):
    """function to create variable integers for get data message
       opposite to the varint function above

    Args:
        count (int): count of bytes to start message

    Returns:
        bytestring: encoded bytsetring from count
    """
    if count < 253:
        countbyte = struct.pack('<B', count)
    elif count == 253:
        countbyte = struct.pack('<H', count)
    elif count == 254:
        countbyte = struct.pack('<I', count)
    else:
        countbyte = struct.pack('<Q', count)
    return countbyte


def createGetData(msg):
    """create get data messsage to request tx and block messages
    Args:
        msg (string): string to make get data out of

    Returns:
        bytestring: encoded bytestring to send
    """
    magic = b'\xf9\xbe\xb4\xd9'
    command = "getdata".encode('utf-8') + b'\x00'*5
    # create the count with a varint
    countbytes = createVarInt(msg['count'])
    # loop through the count and add the hash and index of the vectors we want
    vectors = b''
    for i in range(0,msg['count']):
        vectors += struct.pack('<I', msg['vectdic']["type"+str(i)])
        vectors += msg['vectdic']["hash"+str(i)]
    # payload will be the count and all the vectors concat
    payload = countbytes + vectors
    length = struct.pack('<I', len(payload))
    # take the hash of the hash of the payload first 4 bytes
    checksum = double_sha256(payload)[0:4]
    return magic+command+length+checksum+payload

def createGetAddr():
    """used to get addresses of online nodes. not used here yet

    Returns:
        bytestring: bytestring that would be sent as a message to get online nodes
    """
    magic = b'\xf9\xbe\xb4\xd9'
    command = "getaddr".encode('utf-8') + b'\x00'*5
    checksum = double_sha256(b'')[0:4]
    payload = b''
    length = struct.pack('<I', len(payload))
    return magic + command + length + checksum + payload


# run the program
if __name__ == "__main__":
    print("Welcome to the Bitcoin Trnsaction Viewer")
    print("Connecting to the Bitcoin Network...")

    # connect to peer IP and Port as specified above
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peerIP,peerPort))

    # send the first version message
    # receive version message back
    # if we get this print that we have connected to the node
    s.send(createversionmsg())
    response_data = s.recv(1024)
    if response_data:
        print("Connected to Network\nWaiting for Messages to Arrive")
    # send a verack to the node
    s.send(createverack())

    # loop infinitely so we keep receiving messages
    while True:
        # take in the header first,
        # take 1 byte at a time to avoid an error
        response_data = b''
        while len(response_data) < 24:
            response_data += s.recv(1)
        # decode this and get the length of the payload
        decode_res = decode(response_data)
        lengthpay = decode_res[2]
        # same as above but we loop until we have receive the whole payload
        response_data = b''
        while len(response_data) < lengthpay:
            response_data += s.recv(1)
        # if it's an inv message we parse it, take what we want and send the getdata
        # if it's a tx we parse and print that
        # if it's a block we parse and print that
        # otherwise we go back and receive the next message
        if decode_res[1] == "inv":
            s.send(createGetData(invvectparse(response_data)))
        elif decode_res[1] == 'tx':
            printTx(parsetx(response_data))
        elif decode_res[1] == 'block':
            printBlock(parseblock(response_data))
        else:
            continue

