import socket
import threading
import select
# tcp server:receive data ,get source and destiney address,use function to send data by udp
# thread

localsock = 1081



def tcpServer():
    socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketserver.bind(('0.0.0.0', localsock))
    socketserver.listen(1500)
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
    data = sock.recv(4096)
    print(str(addr))
    print(data)
    sock.send(b'\x05\x00')                 #what hapened here and up there??????
    addressRecv = sock.recv(4096)
    print(addressRecv)
#get address
    address =socket.gethostbyname(addressRecv[5:-2])

    port = addressRecv[-2] * 256 + addressRecv[-1]

    print(str(address)+':'+str(port))

    situ ,sockweb = tcpTest(address,port,sock)
    sock.send(b'\x05'+situ)

    handle_tcp(sock, sockweb)
    '''  
    data =b''
    z = sock.recv(4096)
    print('zzzzzzzzzzzzzzzzzzzzz')
    print(z)
      
    while z != '':
        data=data +z
        z=sock.recv(4096)
    print('data!!!!!!!!!!!!')
    print(data)
    '''

    '''
    while data != '':
        if sockweb.send(data) <=0:
            break

        data2 = b''
        z2 = sockweb.recv(4096)
        while z2 != '':
            data2 = data2 + z2
            z2 = sockweb.recv(4096)
        print('data2')
        print(data2)
        if sock.send(data2) <= 0:
            break

        data = b''
        z = sock.recv(4096)

        while z != '':
            data = data + z
            z = sock.recv(4096)
        print('data!!!!!!!!!!!!!!!!')
        print(data)
    '''

#copy from shadowsocks
def handle_tcp(sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    if remote.send(sock.recv(4096)) <= 0:
                        break
                if remote in r:
                    if sock.send(remote.recv(4096)) <= 0:
                        break
        finally:
            remote.close()


#tcp connet for test use  /have to change
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

def int_to_bytes(value, length):
    result = []

    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)

    result.reverse()

    return result
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