import os
import socket
import struct

from hmac import HMAC
import threading
from X25519 import X25519
from secret import Secret
from general import worker, print_instructions, generate_channel

PROTOCOL_VERSION = struct.pack(">H", 1)
server_id        = b"server"

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
            # PHASE A: Handshake (X25519 + HMAC Authentication)
            print(f"Connected by {addr}")
            message = conn.recv(1024)
            version_client = message[32:34]
            if version_client != PROTOCOL_VERSION:
                print("Version mismatch. Closing connection.")
                conn.close()
                return
            client_id_length = int.from_bytes(message[34:35], byteorder='little')
            client_id = message[35:35+client_id_length]
            B = message[:32]
            shared_secret = exchanger.compute_shared_secret(private_key, B)
            A = exchanger.generate_public_key(private_key)
            conn.sendall(A + PROTOCOL_VERSION + int.to_bytes(len(server_id), byteorder='little') + server_id)
            ## first 32 bytes are the public key, second 2 bytes are the protocol version, 3rd 1 byte is the server_id identity length,4th thing is the identity itself
            mac_gen = HMAC(Secret.PSK)
            mac_rcv = conn.recv(32)
            if mac_rcv != mac_gen.hmac( b"client_auth"+PROTOCOL_VERSION + server_id+client_id + A + B):
                print("Client hasn't been authenticated. Closing connection.")
                conn.close()
                return
            print("Client Authenticated")
            conn.sendall(mac_gen.hmac( b"server_auth"+PROTOCOL_VERSION + server_id+client_id + A + B))
            channel= generate_channel(Secret.PSK,shared_secret,PROTOCOL_VERSION,server_id,conn,server_id)
            t = threading.Thread(target=worker, args=(channel,))
            t.start()
            print_instructions()
            while not channel.closed:
                message= input()
                if message != ":eq":
                    if not channel.closed: channel.send_message(1,message.encode())
                elif not channel.closed:
                    channel.send_message(2,b"")
                    channel.close()

if __name__ == "__main__":
    run_server()