from socket import *
import struct
import sys
import re
 
# receive a datagram
def receiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ''
    except:
        print "An error happened: "
        sys.exc_info()
    return data[0]
 
# get Type of Service: 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}
 
#   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
#   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
#   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
#   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
#   the 7th bit is empty and shouldn't be analyzed
 
    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + \
            reliability[R] + tabs + cost[M]
    return TOS
 
# get Flags: 3 bits
def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}
 
#   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
#   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
#   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13
 
    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags
 
# get protocol: 8 bits
def getProtocol(protocolNr):
    protocolFile = open('Protocol.txt', 'r')
    protocolData = protocolFile.read()
    # new line before the number
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n", "")
        protocol = protocol.replace(str(protocolNr), "")
        protocol = protocol.lstrip()
        return protocol
 
    else:
        return 'No such protocol.'
 
# the public network interface
HOST = gethostbyname(gethostname())
 
# create a raw socket and bind it to the public interface
s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
s.bind((HOST, 0))
 
# Include IP headers
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.ioctl(SIO_RCVALL, RCVALL_ON)
while True:
    data = receiveData(s)
     
    # get the IP header (the first 20 bytes) and unpack them
    # B - unsigned char (1)
    # H - unsigned short (2)
    # s - string
    unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
     
    version_IHL = unpackedData[0]
    version = version_IHL >> 4                  # version of the IP
    IHL = version_IHL & 0xF                     # internet header length
    TOS = unpackedData[1]                       # type of service
    totalLength = unpackedData[2]
    ID = unpackedData[3]                        # identification
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]                       # time to live
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress = inet_ntoa(unpackedData[8])
    destinationAddress = inet_ntoa(unpackedData[9])
     
     
    print "An IP packet with the size %i was captured." % (unpackedData[2])
    print "Raw data: " + ":".join("{:02x}".format(ord(c)) for c in data) # data
    print "\nParsed data"
    print "Version:\t\t" + str(version)
    print "Header Length:\t\t" + str(IHL*4) + " bytes"
    print "Type of Service:\t" + getTOS(TOS)
    print "Length:\t\t\t" + str(totalLength)
    print "ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")"
    print "Flags:\t\t\t" + getFlags(flags)
    print "Fragment offset:\t" + str(fragmentOffset)
    print "TTL:\t\t\t" + str(TTL)
    print "Protocol:\t\t" + getProtocol(protocolNr)
    print "Checksum:\t\t" + str(checksum)
    print "Source:\t\t\t" + sourceAddress
    print "Destination:\t\t" + destinationAddress
    # print "Payload:\n" + ":".join("{:02x}".format(ord(c)) for c in data[20:]) # data[20:]

    print "Payload:\n"
    # IP header length
    iph_length = IHL*4
    # TCP protocol
    if protocolNr == 6:
        tcp_header = data[iph_length:iph_length+20]
        #now unpack them :)
        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
        
        #get data from the packet
        # data = data[h_size:]
        h_size = iph_length + tcph_length * 4

    #ICMP Packets
    elif protocolNr == 1 :
        icmp_header = data[iph_length:iph_length+4]
        #now unpack them :)
        icmph = struct.unpack('!BBH' , icmp_header)
             
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
             
        print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
        h_size = iph_length + icmph_length

    #UDP packets
    elif protocolNr == 17 :
        udph_length = 8
        udp_header = data[iph_length:iph_length+8]
 
        #now unpack them :)
        udph = struct.unpack('!HHHH' , udp_header)
             
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
             
        print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
             
        h_size = iph_length + udph_length

    else:
        h_size = iph_length
        print 'Protocol other than TCP/UDP/ICMP'

    data_size = len(data) - h_size
    #payload= reduce(lambda x,y: x + hex(ord(y))[2:], data[h_size:],'')
    #get data from the packet
    payload=''
    for i in range(h_size,len(data),2):
        try:
            c = data[i:i+2].decode()
        except:
            c = '.'
        payload += c
    # data = data[h_size:]
    
     
    print 'Data: ' + payload
    print "\n\t\t"
# disabled promiscuous mode
s.ioctl(SIO_RCVALL, RCVALL_OFF)
