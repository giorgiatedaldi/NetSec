# Network Security project: Textual-based Transport Layer Security protocol (TTLS)
### Project objective

The objective of this project is to implement a text-based transport layer security protocol (TTLS). The protocol run on top of TCP and it includes a handshake phase where the two parties (the client and the server) securely establish a secret key, and a data phase where the secret key is used to protect exchanged data.
The protocol runs between a client and a server, using TCP transport protocol. Server port 7022 is used by default. 

### Handshake procedure
After a TCP connection is established between client and server, the following Handshake procedure is run:

- C -> S: ClientHello
- S -> C: ServerHello
- S -> C: ServerCertificate
- S -> C: ServerCertificateVerify
- S -> C: ServerFinished
- C -> S: ClientFinished

### Data transmission:
After the handshake procedure successfully completed, both client and server can send messages that are transmitted encrypted with the new established symmetric secret key.

### Message specification
All messages are text-based and have the following format:
Message = MessageType SP Field [SP Field] CRLF
- MessageType = the message type; it can have one of the following values: "HELLO", "CERTIFICATE", "CERTIFICATE_VERIFY", "FINISHED", "DATA", "ERROR";
- SP = the space character ' ';
- Field = a textual message-specific filed; if more fields are present, they are separate by a SP;
- CRLF = the sequence of the carriage return '\r' and line-feed '\n' characters, used as message delimiter.

### ClientHello Message
It is used by the client to send its DH public value Yc. The message format is:
HELLO SP Yc CRLF
- Yc = decimal integer representation of the DH public value

### ServerHello Message
It is used by the client to send its DH public value Ys. The message format is:
HELLO SP Ys CRLF
- Ys = decimal integer representation of the DH public value

### ServerCertificate Message
It contains the server public key formed by the exponent E and modulus N. The message format is:
CERTIFICATE SP E SP N CRLF
- E = decimal integer representation of public exponent
- N = decimal integer representation of the modulus

### ServerCertificateVerify Message
It contains the server signature onto the two DH public values Yc and Ys. The message format is:
CERTIFICATE_VERIFY SP Signature CRLF
- Signature = Sign(KR_S,Yc||Ys);
- KR_S = server private key {D,N};
- Yc||Ys = concatenation of the two strings representing the Yc and Ys values contained into the two HELLO messages;
- Sign = SHA256(bytes(Yc||Ys)) RSA signature computed as power of  D  modulo N of the integer value of the SHA256 hash of the ASCII byte encoding of the Yc||Ys string concatenation; the signature is reported as decimal representation of the integer result of the calculation.

### ServerFinished Message
It contains the MAC value of the server certificate computed with a SecretKey derived from the DH secret. It is used as explicit secret key confirmation by the server. The message format is:
FINISHED SP MAC_S CRLF
- MAC_S = SHA256(SecretKey||bytes(Signature));
- SecretKey = last 16 bytes (128 bits) of the byte-encoding of the DH secret;
- bytes(Signature) = byte-encoding of the Signature field of the CERTIFICATE_VERIFY message.

### ClientFinished Message
It contains the MAC value of MAC_S filed (previous messaged) computed with the SecretKey derived from the DH secret. It is used as explicit secret key confirmation by the client. The message format is:
FINISHED SP MAC_C CRLF
- MAC_C = SHA256(SecretKey||MAC_S).

### Data Message
It is used by both client and server to send data, after the handshake successfully completed. The message format is:
DATA SP Ciphertext64 CRLF
- Ciphertext64 = Base64(Ciphertext) = base64 encoding of the ciphertext 
- Ciphertext = AES128-CBC-PKCS5Padding(SecretKey,Cleartext) = AES encryption in CBC mode with IV=0 (16 zero bytes) of a Cleartext
- Cleartext = byte encoding of a textual message

### Error Message
It is sent by the server in case of an error (wrong message format, verification of the client MAC failed, error in decrypting a data messages, etc.).  The message format is:
ERROR SP ErrorMessage CRLF 
- ErrorMessage = textual message describing the error.
