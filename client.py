import socket
import threading
import select
# tcp server:receive data ,get source and destiney address,use function to send data by udp
# thread
localsock = 1081
listenNumber = 1500
socksList = {}
server = ('127.0.0.1',8621)
bufferSize = 65535

def tcpServer():
    socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketserver.bind(('0.0.0.0', localsock))
    socketserver.listen(listenNumber)
    while True:
        sock, addr = socketserver.accept()
        print(str(addr)+'connect')
        t = threading.Thread(target=sockHandler, args=(sock, addr))
        t.start()

#sockethandler
def sockHandler(sock, sourceAddress):
    data = sock.recv(1024)                    #this hasn't been used for the reason down there
    print('Data i think useless')
    print(data)
    if data != b'\x05\x01\x00':
        sock.close()
        return
    print('sourceAddress')
    print(str(sourceAddress))
    sock.send(b'\x05\x00')                 #other situation is out of my ability and since i have no problem in using it .
    addressRecv = sock.recv(1024)
#get  adrress
    try:
        '''
        if addressRecv ==b'':
            sock.close()
            return
        '''
        addrtype = addressRecv[3]
        print(addressRecv)
        print('address type')
        print(addressRecv[3])
        if addrtype == 1:
            print('destinry address')
            print(addressRecv[5:9])
            addr = socket.inet_ntoa(addressRecv[5:9])
            print('string address')
            port = addressRecv[-2] * 256 + addressRecv[-1]
            tcpSock = tcpSender(None,server,(addr,port),0,0)
        elif addrtype == 3:
            print('hostname address')
            print(addressRecv[5:-2])
            addr = addressRecv[5:-2]
            port = addressRecv[-2] * 256 + addressRecv[-1]
            print(port)
            tcpSock = tcpSender(None, server, (addr,port), 0, 1)
        elif addrtype == 4:                                              #socke type have to change to support ipv6
            print('ípv6')
            addr = socket.inet_ntop(socket.AF_INET6, addressRecv[5:-2])
            port = addressRecv[-2] * 256 + addressRecv[-1]
            tcpSock = tcpSender(None, server, (addr,port), 0, 2)
        else:
            # not support
            print('addr_type not support')
            return

      #  addSocksList(sock, sourceAddress,( addr,port))
        data = tcpSock.recv(4096)
        print('connection report')
        print(data)
        if data[1] == 0:
            connectionReport(sock,data[-1],sourceAddress, ( addr,port))
            if data[-1] == 0:
                return
        elif data[1] == 1:
            addr = socket.inet_ntoa(data[2:6])
            #
            print(addr)
            connectionReport(sock, data[9], sourceAddress, ( addr,port))
            if data[9] == 0 :
                return
            else:
                print('connection situation')
                print(data[9])
        else:
            print('wrong wrong')
        handle_tcp(sock,tcpSock,( addr,port))

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

                data = sock.recv(bufferSize)

                if len(data) <= 0:
                    break
                remote = tcpSend(remote,DataCreate(data,destineyAddress,1,0))
            if remote in r:
                data = remote.recv(bufferSize)
                print('get from server')
                print(data)
                if len(data)>0:
                    sock.send(data[9:])
                else:
                    break
    finally:
        sock.close()
        remote.close()

#tcp connet for test use  /have to change   get
def connectionReport(sock,result,sourceAddress, addr):
    sock_name = sock.getsockname()
    print('connectionn repoty')
    print(sock_name[1])
    server_hex_addr = socket.inet_aton(sock_name[0])
    server_hex_port = port_to_hex_string(sock_name[1])
    print(server_hex_port)
    if result == 1:
        #sock = findSocks(sourceAddress, addr)
        sock.send(b'\x05\x00\x00\x01' + server_hex_addr + server_hex_port)
        return  sock
    else:
        #sock = findSocks(sourceAddress, addr)
        sock.send(b'\x05\x04\x00\x01'+server_hex_addr+server_hex_port)
        sock.close()
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
def tcpSender(data, serverAddr,destineyAddress,mode,addressTypeP):           #ipv6 have to change this
                                                                            #change methode name serveraddr is not proprite
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #here  ipv6
    s.connect(serverAddr)
    data = DataCreate(data, destineyAddress,mode,addressTypeP)
    tcpSend(s,data)
    return s


def DataCreate(data,destineyAddress,mode,addressTypeP):
    protocolType = b'\x00'
    if addressTypeP == 0:
        addressType = b'\x00'
        IpAdress = socket.inet_aton(destineyAddress[0])
    elif addressTypeP == 1:
        addressType = b'\x01'
        IpAdress = destineyAddress[0]
    elif addressTypeP == 2:
        addressType = b'\x02'
                                                                    #possible bug ipv6
    if mode == 0:
        modePart = b'\x00'
    elif mode == 1:
        modePart = b'\x01'

    port = port_to_hex_string(destineyAddress[1])
    if data == None:
        return modePart + addressType + IpAdress + port + protocolType
    return  modePart + addressType + IpAdress + port + protocolType + data

def tcpSend(socks,data):
    socks.send(data)
    return socks

# decrypt

# encrypt


tcpServer()