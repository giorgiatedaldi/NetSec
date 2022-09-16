from Crypto.Cipher import AES

class AES128_CBC_PKCS5:

    '''
    Class constructor.
    '''

    def __init__(self, key):
        self.key = bytes.fromhex(key)
        self.mode = AES.MODE_CBC
        self.size = AES.block_size
        self.iv = bytes.fromhex('00000000000000000000000000000000')

    def pad(self, text):

        '''
        Method to perform PKCS5 padding.
        '''

        byte_array = text.encode('utf-8')
        pad_len = self.size - len(byte_array) % self.size
        return byte_array + (bytes([pad_len]) * pad_len)

    def unpad(self, padded_text):

        '''
        Method to perform PKCS5 unpadding.
        '''

        byte_array = padded_text.decode('utf-8')
        return byte_array[:-ord(byte_array[-1:])]

    def encrypt(self, plaintext):

        '''
        Method to encrypt a text with AES128 CBC mode.
        '''

        cipher = AES.new(self.key, self.mode, iv = self.iv)
        padded = self.pad(plaintext)
        encrypted = cipher.encrypt(padded).hex()
        #b64_encrypted = base64.b64encode(encrypted).decode('utf-8')
        return encrypted

    def decrypt(self, content):
        '''
        Method to decrypt a text with AES128 CBC mode.
        '''
        cipher = AES.new(self.key, self.mode, iv = self.iv)
        ciphertext = bytes.fromhex(content)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = self.unpad(padded_plaintext)
        return plaintext