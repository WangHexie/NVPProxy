import socket
import threading
import select
# tcp server:receive data ,get source and destiney address,use function to send data by udp
# thread

localsock = 1081
listenNumber = 1500


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

# delete address after 100s

# find adress -return  corrosponding address
# have to handle the situation there is no read while delete or  the opposite

#sockethandler
def sockHandler(sock, addr):
    data = sock.recv(4096)                    #this hasn't been used for the reason down there
    print(str(addr))
    sock.send(b'\x05\x00')                 #other situation is out of my ability ,since i have no problem in using it .
    addressRecv = sock.recv(4096)
#get  adrress
    try:
        addrtype = addressRecv[3]
        if addrtype == 1:
            addr = socket.inet_ntoa(addressRecv[5:-2])
        elif addrtype == 3:
            addr = socket.gethostbyname(addressRecv[5:-2])
        elif addrtype == 4:                                              #socke type have to change to support ipv6
            addr = socket.inet_ntop(socket.AF_INET6, addressRecv[5:-2])
        else:
            # not support
            print('addr_type not support')
            return
        port = addressRecv[-2] * 256 + addressRecv[-1]

        situ, sockweb = tcpTest(addr, port, sock)
        sock.send(b'\x05' + situ)
        handle_tcp(sock, sockweb)
    except socket.error :
        print('socket errot')


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

def handle_tcp(sock, remote):
    try:
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                if len(data) <= 0:
                    break
                result = send_all(remote, data)
                if result < len(data):
                    raise Exception('failed to send all data')
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
def tcpTest(address,port,sock):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_name = sock.getsockname()
    server_hex_addr = socket.inet_aton(sock_name[0])
    server_hex_port = port_to_hex_string(sock_name[1])
    print(server_hex_port)
    try:
        s.connect((address, port))

    except socket.timeout:
        return b'\x04\x00\x01'+server_hex_addr+server_hex_port ,s
    except:
        return b'\x04\x00\x01'+server_hex_addr+server_hex_port ,s
    return b'\x00\x00\x01'+server_hex_addr+server_hex_port ,s


#port_to_hex_string done by copy
def port_to_hex_string(int_port):
    port_hex_string = bytes([int_port//256])+bytes([int_port%256])
    return port_hex_string
# udp sender
def udpSender(sock, addr):
    return


 # udp receiver
def udpReceiver():
    return
# thread

# decrypt

# encrypt


tcpServer()