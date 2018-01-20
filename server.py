import socket
import threading
import select

'''
client(source) ----------------->proxy server ---------> server (destiney)
'''

localsock = 1081
listenNumber = 1500
localPort = 8621
bufferSize = 65535
socksList = {}


#port_to_hex_string done by copy
def port_to_hex_string(int_port):
    port_hex_string = bytes([int_port//256])+bytes([int_port%256])
    return port_hex_string

def hex_string_to_port(hex_string):
    return hex_string[-2] * 256 + hex_string[-1]

def handle_tcp(sock,remote,sourceAddr,destineyAddress):        #some problems here no idea how to solve
        fdset = [sock,remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:

                data = sock.recv(bufferSize)

                print('tcpdata')
                print(data)
                if len(data) > 0:
                    remote = tcpSend(remote,dataCreate(data,destineyAddress,1,0),sourceAddr)
                else:
                    print('im done')
                    break
            if remote in r:
                data = remote.recv(bufferSize)
                print('remote data')
                print(data)
                if len(data)<=0:
                    break
                sock.send(data[9:])
        sock.close()
        remote.close()





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

'''
# udp sender  fomat is down there ; 
-----------------------------------------------
if connetion is good data part is 1 else = 0
_______________________________________________
'''


def tcpSender(data, sourceAddr, destineyAddress, mode, addressTypeP,socks):  # ipv6 have to change this
    # change methode name serveraddr is not proprite

    data = dataCreate(data, destineyAddress, mode, addressTypeP)
    tcpSend(socks, data, sourceAddr)
    return socks


def dataCreate(data, destineyAddress, mode, addressTypeP):
    protocolType = b'\x00'
    if addressTypeP == 0:
        addressType = b'\x00'
    elif addressTypeP == 1:
        addressType = b'\x01'
    elif addressTypeP == 2:
        addressType = b'\x02'

    if mode == 0:
        modePart = b'\x00'
    elif mode == 1:
        modePart = b'\x01'
    if addressTypeP == 0:
        IpAdress = socket.inet_aton(destineyAddress[0])
    elif addressTypeP == 2:
        IpAdress = socket.inet_aton(socket.AF_INET6,destineyAddress[0])
    elif addressTypeP == 1:
        IpAdress = socket.inet_aton(destineyAddress[0])
    port = port_to_hex_string(destineyAddress[1])
    if data == None:
        return modePart + addressType + IpAdress + port + protocolType
    return modePart + addressType + IpAdress + port + protocolType + data


def tcpSend(socks, data, serverAddr):
    socks.send(data)
    return socks

 # udp receiver
def tcpServer():
    print('1')
    tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpSock.bind(('0.0.0.0', localPort))
    tcpSock.listen(listenNumber)
    while True:
        sock, addr = tcpSock.accept()
        print('Received from %s:%s.' % addr)
        t = threading.Thread(target=tcpDataHandler, args=(sock, addr))
        t.start()

    return
# thread udp handle


def tcpDataHandler(sock, addr):
    data = sock.recv(4096)
    dataHandler(data,addr,sock)
#
def dataHandler(data,sourceAddr,sock):
        if data[1] == 0:
            destineyAddress = (socket.inet_ntoa(data[2:6]), hex_string_to_port(data[6:8]))
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print('address ddfa')
                print(data[2:6])
                s.connect(destineyAddress)
            except:
                tcpSender(b'\x00',sourceAddr,destineyAddress,0,0,sock)
            finally:
                sock = tcpSender(b'\x01',sourceAddr,destineyAddress,0,0,sock)
                handle_tcp(s,sock,sourceAddr,destineyAddress)
        elif data[1] == 1:

            b = data[2:-3]
            desIpAddress = (socket.gethostbyname(data[2:-3]),hex_string_to_port(data[-3:-1] )) # ipv6 support need to change this
            try:
                a = socket.gethostbyname(data[2:-3])
                print(desIpAddress)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(desIpAddress)
            except:
                sock = tcpSender(b'\x00' + data[2:-3], sourceAddr, desIpAddress, 0,1,sock)
            finally:
                sock = tcpSender(b'\x01'+data[2:-3], sourceAddr,desIpAddress, 0,1,sock)
                handle_tcp(s,sock,  sourceAddr, desIpAddress)
        elif data[1] == 2:
            destineyAddress = (socket.inet_ntoa(data[2:-3]), hex_string_to_port(data[-2:-1]))
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.connect(destineyAddress)
            except:
                sock = tcpSender(b'\x00', sourceAddr, destineyAddress,0,2,sock)
            finally:
                sock = tcpSender(b'\x01', sourceAddr, destineyAddress,0,2,sock)
                handle_tcp( s,sock, sourceAddr, destineyAddress)

tcpServer()