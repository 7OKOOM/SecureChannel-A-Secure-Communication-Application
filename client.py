import socket

import config
from X25519 import X25519


def run_client(host='127.0.0.1', port=65432):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        exchanger = X25519()
        B = exchanger.generate_public_key()

        # PHASE A: Handshake
        # TODO: Perform key exchange and verify PSK-based transcript

        # PHASE B: Secure Messaging
        message = b"Hello, Secure World!"
        # TODO: Encrypt message with AEAD
        s.sendall(message)

        data = s.recv(1024)
        # TODO: Decrypt response
        print(f"Received (decrypted): {data}")

if __name__ == "__main__":
    run_client()