import socket
import threading
import select

'''
client(source) ----------------->proxy server ---------> server (destiney)
'''

localsock = 1081
listenNumber = 1500
localPort = 8621

socksList = {}



#copy from shadowsocks . Have to change it later!!!!!!
def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

#port_to_hex_string done by copy
def port_to_hex_string(int_port):
    port_hex_string = bytes([int_port//256])+bytes([int_port%256])
    return port_hex_string

def hex_string_to_port(hex_string):
    return hex_string[-2] * 256 + hex_string[-1]


#route list
def findSocks(sourceAdress,destineyAddress):
    return socksList[(sourceAdress,destineyAddress)]

def delSocks(sourceAdress,destineyAddress):
    socksList[(sourceAdress,destineyAddress)]=None

def closeSocks(socks,sourceAddress,destineyAddress):
    socks.close()
    delSocks(sourceAddress,destineyAddress)
# delete address after 100s

# find adress -return  corrosponding address
# have to handle the situation there is no read while delete or  the opposite



def handle_tcp(sock,sourceAddr,destineyAddress):
    try:
        fdset = [sock]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                if len(data) <= 0:
                    break
                result = udpSender(data,sourceAddr,1)
                if result < len(data):
                    raise Exception('failed to send all data')
    finally:
        closeSocks(sock,sourceAddr,destineyAddress)

def addSocksList(socks,sourceAdress,destineyAddress):
    socksList[(sourceAdress,destineyAddress)]=socks

'''
udp data format 
--------------------------------------------------------------------------------------------------------------------------------------------------------
1 byte for mode switch|1 bytes for address type | a few bytes for destiney address |2 bytes for port | 1 bytes for udp or something else |left for data| 
---------------------------------------------------------------------------------------------------------------------------------------------------------

mode :
0:test connection and get ip address by hostname
1:normal data transport

address type :
0:ipv4   : 4 bytes
1: hostname
2:ipv6   :16 bytes

protocol type:
-NO SUPPORT-
0: defalt
'''

# udp sender  fomat is down there ; if connetion is good data part is 1 else = 1
def udpSender(data, sourceAddr,destineyAddress,mode):           #ipv6 have to change this
    addressType = b'0'
    protocolType = b'0'
    if mode == 0:
        modePart=b'0'
    elif mode == 1:
        modePart = b'1'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #here  ipv6
    IpAdress = socket.inet_aton(destineyAddress[0])
    port = port_to_hex_string(destineyAddress[1])
    s.sendto(sourceAddr, modePart + addressType + IpAdress + port + protocolType+data)
    s.close()
    return s


 # udp receiver
def udpReceiver():
    udpSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSock.bind(('127.0.0.1', localPort))
    while True:
        data, addr = udpSock.recvfrom(4096)
        print('Received from %s:%s.' % addr)
        t = threading.Thread(target=udpDataHandler, args=(data, addr))
        t.start()

    return
# thread udp handle



#
def udpDataHandler(data,sourceAddr):
    if data[0] == 0:
        if data[1] == 0:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                destineyAddress = (socket.inet_ntoa(data[2:6]) ,hex_string_to_port(data[6:8]) )
                s.connect(destineyAddress)
                addSocksList(s,sourceAddr,destineyAddress)
            except:
                return udpSender(b'0',sourceAddr,destineyAddress,0)
            finally:
                udpSender(b'1',sourceAddr,destineyAddress,0)
        elif data[1] == 1:
            try:
                desIpAddress = socket.gethostbyname(data[2:-3])                          #ipv6 support need to change this
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((desIpAddress, hex_string_to_port(data[-2:-1])))
                addSocksList(s,sourceAddr,desIpAddress)

            except:
                return udpSender(b'0', sourceAddr,desIpAddress, 0)
            finally:
                udpSender(b'1', sourceAddr,desIpAddress, 0)
        elif data[1] == 2:
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                destineyAddress = (socket.inet_ntoa(data[2:-3]), hex_string_to_port(data[-2:-1]))
                s.connect(destineyAddress)
                addSocksList(s,sourceAddr,destineyAddress)
            except:
                return udpSender(b'0', sourceAddr, destineyAddress,0)
            finally:
                udpSender(b'1', sourceAddr, destineyAddress,0)
    elif data[0] == 1:
        if data[1] == 0:
            try:
                s = findSocks(sourceAddr,(socket.inet_ntoa(data[2:6]), hex_string_to_port(data[6:8])))
                if s == None:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((socket.inet_ntoa(data[2:6]), hex_string_to_port(data[6:8])))
                s.send(data[8:])

                handle_tcp(s,sourceAddr,(socket.inet_ntoa(data[2:6]), hex_string_to_port(data[6:8])))
            except:
                return
            finally:
                return


    return



# decrypt

# encrypt


udpReceiver()