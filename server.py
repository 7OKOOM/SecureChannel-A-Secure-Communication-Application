import os
import socket

from hdkf import HKDF
from hmac import HMAC

from X25519 import X25519
from secret import Secret

PROTOCOL_VERSION = b"SecureChannel"
CLIENT_ID        = b"client"
SERVER_ID        = b"server"

def run_server(host='127.0.0.1', port=65432):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        exchanger = X25519()
        private_key = bytearray(os.urandom(32))
        conn, addr = s.accept()
        with conn:
            # PHASE A: Handshake (Implement X25519 + HMAC Authentication)
            print(f"Connected by {addr}")
            B = conn.recv(32)
            shared_secret = exchanger.compute_shared_secret(private_key, B)
            A = exchanger.generate_public_key(private_key)
            conn.sendall(A)
            mac_gen = HMAC()
            mac = mac_gen.hmac(Secret.PSK,PROTOCOL_VERSION+CLIENT_ID+SERVER_ID+A+B)
            mac_rcv = conn.recv(32)
            conn.sendall(mac)
            if mac_rcv != mac:
                print("Client hasn't been authenticated. Closing connection.")
                conn.close()
                return
            print("mac received correctly!")
            mixer = HKDF()
            key = mixer.hkdf(Secret.PSK,shared_secret,"p1",88)
            key_server_to_client = key[:32]
            key_client_to_server = key[32:64]
            nonce_server_to_client = key[64:76]
            nonce_client_to_server = key[76:]


            # PHASE B: Secure Messaging (ChaCha20-Poly1305)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                # TODO: Decrypt received message using AEAD
                print(f"Received (encrypted): {data}")

                # TODO: Encrypt and send response
                conn.sendall(data)

if __name__ == "__main__":
    run_server()