import socket
import threading
import select
# tcp server:receive data ,get source and destiney address,use function to send data by udp
# thread
localsock = 1081
listenNumber = 1500
socksList = {}
server = ('127.0.0.1',8621)

def tcpServer():
    socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketserver.bind(('0.0.0.0', localsock))
    socketserver.listen(listenNumber)
    while True:
        sock, addr = socketserver.accept()
        print(str(addr)+'connect')
        t = threading.Thread(target=sockHandler, args=(sock, addr))
        t.start()

# address list  [[source,destiney,time],[,,]]
def findSocks(sourceAdress,destineyAddress):
    return socksList[(sourceAdress,destineyAddress)]

def delSocks(sourceAdress,destineyAddress):
    socksList[(sourceAdress,destineyAddress)]=None

def closeSocks(socks,sourceAddress,destineyAddress):
    socks.close()
    delSocks(sourceAddress,destineyAddress)

def addSocksList(socks,sourceAdress,destineyAddress):
    socksList[(sourceAdress,destineyAddress)]=socks
# delete address after 100s

# find adress -return  corrosponding address
# have to handle the situation there is no read while delete or  the opposite

#sockethandler
def sockHandler(sock, sourceAddress):
    data = sock.recv(4096)                    #this hasn't been used for the reason down there
    print(str(sourceAddress))
    sock.send(b'\x05\x00')                 #other situation is out of my ability and since i have no problem in using it .
    addressRecv = sock.recv(4096)
#get  adrress
    try:
        addrtype = addressRecv[3]
        if addrtype == 1:
            addr = socket.inet_ntoa(addressRecv[5:-2])
            port = addressRecv[-2] * 256 + addressRecv[-1]
            udpSock = udpSender(None,sourceAddress,(addr,port),0,0)
        elif addrtype == 3:
            addr = addressRecv[5:-2]
            port = addressRecv[-2] * 256 + addressRecv[-1]
            udpSock = udpSender(None, sourceAddress, (addr,port), 0, 1)
        elif addrtype == 4:                                              #socke type have to change to support ipv6
            addr = socket.inet_ntop(socket.AF_INET6, addressRecv[5:-2])
            port = addressRecv[-2] * 256 + addressRecv[-1]
            udpSock = udpSender(None, sourceAddress, (addr,port), 0, 2)
        else:
            # not support
            print('addr_type not support')
            return

        addSocksList(sock, sourceAddress, addr)
        data = udpSock.recv(4096)
        if data[1] == 0:
            connectionReport(sock,data[-1],sourceAddress, addr)
        elif data[1] == 1:
            addr = socket.inet_ntoa(data[-4:])
            addSocksList(sock, sourceAddress, addr)
            connectionReport(sock, data[-1], sourceAddress, addr)

        handle_tcp(sock,udpSock,addr)

    finally:
        print('????')


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

def handle_tcp(sock, remote,destineyAddress):
    try:
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                remote = udpSend(remote,server,udpDataCreate(data,destineyAddress,1,0))
            if remote in r:
                data = remote.recv(4096)
                if len(data) <= 0:
                    break
                result = send_all(sock, data)
                if result < len(data):
                    raise Exception('failed to send all data')
    finally:
        sock.close()
        remote.close()

#tcp connet for test use  /have to change   get
def connectionReport(sock,result,sourceAddress, addr):
    sock_name = sock.getsockname()
    server_hex_addr = socket.inet_aton(sock_name[0])
    server_hex_port = port_to_hex_string(sock_name[1])
    print(server_hex_port)
    if result == 1:
        sock = findSocks(sourceAddress, addr)
        sock.send(b'\x05\x04\x00\x01' + server_hex_addr + server_hex_port)
        return  sock
    else:
        sock = findSocks(sourceAddress, addr)
        sock.send(b'\x05\x00\x00\x01'+server_hex_addr+server_hex_port)
        return sock

#sockshandler
def connectionHandler():
    return

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
def udpSender(data, serverAddr,destineyAddress,mode,addressTypeP):           #ipv6 have to change this
                                                                            #change methode name serveraddr is not proprite
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #here  ipv6
    data = udpDataCreate(data, destineyAddress,mode,addressTypeP)
    udpSend(s,data, serverAddr)
    return s


def udpDataCreate(data,destineyAddress,mode,addressTypeP):
    protocolType = b'0'
    if addressTypeP == 0:
        addressType = b'0'
    elif addressTypeP == 1:
        addressType = b'1'
    elif addressTypeP == 2:
        addressType = b'2'

    if mode == 0:
        modePart = b'0'
    elif mode == 1:
        modePart = b'1'
    if addressTypeP == 0:
        IpAdress = socket.inet_aton(destineyAddress[0].decode("utf-8"))
    elif addressTypeP == 1:
        IpAdress = destineyAddress[0]
    port = port_to_hex_string(destineyAddress[1])
    if data == None:
        return modePart + addressType + IpAdress + port + protocolType
    return  modePart + addressType + IpAdress + port + protocolType + data

def udpSend(socks,data,serverAddr):
    socks.sendto(data,serverAddr)
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


tcpServer()