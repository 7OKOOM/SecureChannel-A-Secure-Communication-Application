import socket

from chacha20_poly1305_AEAD import ChaCha20Poly1305
from hdkf import HKDF
from hmac import HMAC

from X25519 import X25519
import os

from secret import Secret
from secure_channel import SecureChannel

PROTOCOL_VERSION = b"\x00\x01"
print(PROTOCOL_VERSION)
client_id        = b"client"

def run_client(host='127.0.0.1', port=65432):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # PHASE A: Handshake
        exchanger = X25519()
        private_key = bytearray(os.urandom(32))
        B = exchanger.generate_public_key(private_key)

        s.sendall(B + PROTOCOL_VERSION + int.to_bytes(len(client_id), byteorder='little') + client_id)
        message = s.recv(1024)
        A = message[:32]
        version_server = message[32:34]
        if version_server != PROTOCOL_VERSION:
            print("Version mismatch. Closing connection.")
            s.close()
            return
        server_id_length = int.from_bytes(message[34:35], byteorder='little')
        server_id = message[35:35+server_id_length]
        shared_secret = exchanger.compute_shared_secret(private_key,A)
        mac_gen = HMAC()
        s.sendall(mac_gen.hmac(Secret.PSK, b"client_auth"+PROTOCOL_VERSION + server_id+client_id + A + B))

        mac_rcv = s.recv(32)
        if mac_rcv != mac_gen.hmac(Secret.PSK, b"server_auth"+PROTOCOL_VERSION + server_id+client_id + A + B):
            print("Server hasn't been authenticated. Closing connection.")
            s.close()
            return

        print("mac received correctly!")
        mixer = HKDF()
        key = mixer.hkdf(Secret.PSK,shared_secret,PROTOCOL_VERSION+b" PhaseB keys and nonces",88)

        key_server_to_client = key[:32]
        key_client_to_server = key[32:64]
        nonce_server_to_client = key[64:76]
        nonce_client_to_server = key[76:]

        channel = SecureChannel(s,key_client_to_server,key_server_to_client,nonce_client_to_server,nonce_server_to_client,PROTOCOL_VERSION)
        channel.send_message(1,b"Wadee is the goat",client_id)
        channel.send_message(2,b"exiting",client_id)
        s.close()


if __name__ == "__main__":
    run_client()