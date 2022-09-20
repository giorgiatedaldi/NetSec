import socket
from Crypto.Hash import SHA256
from AESCipher import AES128_CBC_PKCS5

class MySocket:

    '''
    Class constructor.
    '''

    def __init__(self, sock=None):
        if sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self._sock = sock
        self._server_hello = []
        self._server_certificate = []
        self._server_certificate_verify = []
        self._server_finished = []
        self._g = None
        self._p = None
        self._xc = None
        self._yc = None
        self._secret_key = None

    def connect_to_server(self, host, port):

        '''
        Method to connect to the server.
        '''

        self._sock.connect((host, port))


    def send_hello_message(self):

        '''
        Method to build and send the ClientHello message to the server.
        '''

        print('ClientHello message: ')
        client_hello = 'HELLO' + ' ' + str(self._yc) + '\r\n'
        print(client_hello)
        self.send_message(client_hello)


    def receive_server_hello_certificate_message(self):

        '''
        Method to receive the server response to the ClientHello message. It saves and formats ServerHello, ServerCertificate, ServerCertificateVerify and ServerFinished
        messages.
        '''

        self._server_hello, self._server_certificate, self._server_certificate_verify, self._server_finished = self.read_server_hello_certificate_message().split('\r\n', 3)
        self._server_hello = self._server_hello.split(' ')
        self._server_certificate = self._server_certificate.split(' ')
        self._server_certificate_verify = self._server_certificate_verify.split(' ')
        self._server_finished = self._server_finished.split(' ')

        print('ServerHello message:\n', self._server_hello)
        print('ServerCertificate message:\n', self._server_certificate)
        print('ServerCertificateVerify message:\n', self._server_certificate_verify)
        print('ServerFinished message:\n', self._server_finished)

    def compute_secret_key(self):

        '''
        Method to compute the secret key that are the last 16 bytes of the Diffie-Hellman secret.
        '''

        dh_secret = hex(pow(int(self._server_hello[1]), self._xc, self._p))
        print('Diffie-Hellman secret:\n', dh_secret)
        self._secret_key = dh_secret[-32:]
        print('Secret Key:\n', self._secret_key)

    def compute_signature(self, signature):

        '''
        Method to compute e verify the signature.
        '''

        bytes_signature = hex(int(self._server_certificate_verify[1]))[2:]
        hashed = SHA256.new(bytes.fromhex(self._secret_key + bytes_signature)).hexdigest()
        if (hashed == signature):
            print('Signature verified:\n', hashed)
        else:
            print('Invalid signature')

    def send_client_finished_message(self):

        '''
        Method to compute the mac client value (MAC_C = SHA256(secretKey||MAC_S)) and send it to the server.
        '''

        mac_s = self._server_finished[1]
        mac_c = SHA256.new(bytes.fromhex(self._secret_key + mac_s)).hexdigest()
        print('Mac client:\n', mac_c)
        client_finished = 'FINISHED' + ' ' + str(mac_c) + '\r\n'
        self.send_message(client_finished)

    def handshake(self, g, p, xc):

        '''
        Method to execute the handshake procedure.
        '''
        print('---------- HANDSHAKE ----------')
        self._g = g
        self._p = p
        self._xc = xc
        self._yc = pow(g, xc, p)
        self.send_hello_message()
        self.receive_server_hello_certificate_message()
        self.compute_secret_key()
        self.compute_signature(self._server_finished[1])
        self.send_client_finished_message()
        print('------------------------------\n')
    def receive_byte_from_server(self):

        '''
        Method receive data from server.
        '''

        server_data = self.read_data_message().strip().split(' ')
        print('ServerData message:\n', server_data)
        return server_data

    def decrypt_data_message(self):

        '''
        Method decrypt data from server.
        '''

        print('---------- DECRYPT DATA ----------')
        server_data = self.receive_byte_from_server()
        #server_data = self.read_data_message().strip().split(' ')
        #print('ServerData message:\n', server_data)
        AES_obj = AES128_CBC_PKCS5(self._secret_key)
        decrypted = AES_obj.decrypt(server_data[1])
        print('Decrypted message:\n', decrypted)
        print('------------------------------\n')

    def send_data_message(self, msg):

        '''
        Method to send the encrypted data to the server.
        '''

        print('---------- SEND DATA ----------')
        print('Message to send:\n', msg)
        AES_obj = AES128_CBC_PKCS5(self._secret_key)
        ciphertext = AES_obj.encrypt(msg)
        print('Encrypted message:\n', ciphertext)
        client_data = 'DATA' + ' ' + ciphertext + '\r\n'
        self.send_message(client_data)
        print('ClientData message:\n', client_data)
        server_data = self.receive_byte_from_server()
        print('------------------------------\n')

    def send_message(self, string_msg):

        '''
        Method to send a generic message to the server.
        '''

        self._sock.sendall(string_msg.encode())

    def read_server_hello_certificate_message(self):

        '''
        Method to read from the socket the bytes that contain ServerHello, ServerCertificate, ServerCertificateVerify and ServerFinished messages.
        '''

        buffer = ""
        while True:
            data = self._sock.recv(4096)
            buffer += data.decode()
            if buffer.count('\r\n') == 4:
                break
        return buffer.strip()

    def read_data_message(self):

        '''
        Method to read from the socket the bytes that contain the encrypted messages from the server
        '''

        buffer = ""
        while True:
            data = self._sock.recv(4096)
            buffer += data.decode()
            if '\r\n' in buffer:
                break
        return buffer.strip()

