import socket

from hdkf import HKDF
from hmac import HMAC

from X25519 import X25519
import os
from secret import Secret
PROTOCOL_VERSION = b"SecureChannel"
CLIENT_ID        = b"client"
SERVER_ID        = b"server"

def run_client(host='127.0.0.1', port=65432):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # PHASE A: Handshake (Implement X25519 + HMAC Authentication)
        exchanger = X25519()
        private_key = bytearray(os.urandom(32))
        B = exchanger.generate_public_key(private_key)
        s.sendall(B)
        A =    s.recv(32)
        shared_secret = exchanger.compute_shared_secret(private_key,A)
        mac_gen = HMAC()
        mac = mac_gen.hmac(Secret.PSK,PROTOCOL_VERSION+CLIENT_ID+SERVER_ID+A+B)
        s.sendall(mac)
        mac_rcv = s.recv(32)
        if mac_rcv != mac:
            print("Server hasn't been authenticated. Closing connection.")
            s.close()
            return
        print("mac received correctly!")
        mixer = HKDF()
        key = mixer.hkdf(Secret.PSK,shared_secret,"p1",88)
        key_server_to_client = key[:32]
        key_client_to_server = key[32:64]
        nonce_server_to_client = key[64:76]
        nonce_client_to_server = key[76:]


        # PHASE B: Secure Messaging
        message = b"Hello, Secure World!"
        # TODO: Encrypt message with AEAD
        s.sendall(message)

        data = s.recv(1024)
        # TODO: Decrypt response
        print(f"Received (decrypted): {data}")

if __name__ == "__main__":
    run_client()