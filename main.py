#from message import Message
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
from Crypto.Hash import SHA256

HOST = "netsec.unipr.it"  # The server's hostname or IP address
PORT = 7022  # The port used by the server
g = 2
p = 171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303
xc = 581653603720443212670038328865006257879554410432796221735023975689267215344537985570480348929339571200971269505146865970287397758935553477713134007735884

def receive_message(sock):
    buffer = ""
    while True:
        data = sock.recv(4096)
        buffer += data.decode()
        if buffer.count('\r\n') == 4:
            break
    return buffer

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    yc = pow(g, xc, p)
    #client_hello = Message('HELLO', [str(yc)]).getMessage()
    client_hello = 'HELLO'+' '+str(yc)+'\r\n'
    print(client_hello)
    sock.sendall(client_hello.encode())
    hello, certificate, certificate_verify, server_finished = receive_message(sock).split('\r\n', 3)
    hello = hello.split(' ')
    certificate = certificate.split(' ')
    certificate_verify = certificate_verify.split(' ')
    server_finished = server_finished.split(' ')
    print(hello)
    print(certificate)
    print(certificate_verify)
    print(server_finished)

    dh_secret = hex(pow(int(hello[1]), xc, p))
    print(dh_secret)

    secret_key = dh_secret[-32:]
    print(secret_key)

    bytes_signature = hex(int(certificate_verify[1]))[2:]
    print(bytes_signature)

    hashed = SHA256.new((secret_key + bytes_signature).encode()).hexdigest()
    print(hashed)

    mac_c = SHA256.new((secret_key + server_finished[1]).encode()).hexdigest()
    print(mac_c)

    #clientFinished = Message('FINISHED', [str(mac_c)]).getMessage()
    client_finished = 'FINISHED' + ' ' + str(mac_c) + '\r\n'
    sock.sendall(client_finished.encode())

    '''
    print('DATA MESSAGE')
    message = 'Test message'
    message = "".join("{:02x}".format(ord(c)) for c in message)

    #dataMessage = hex('Test message'.encode())
    cipher = AES.new(secretKey.encode(), AES.MODE_CBC)
    ct = cipher.encrypt(pad(message.encode(), AES.block_size, style='pks5'))
    print(ct)
    ct_64 = base64.b64encode(ct)
    print(ct_64)
    '''
if __name__ == "__main__":
    main()