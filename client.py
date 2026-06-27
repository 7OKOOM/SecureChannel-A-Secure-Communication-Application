import socket
import struct

from hmac import HMAC
import threading
from X25519 import X25519
import os

from secret import Secret
from general import worker, print_instructions, generate_channel
PROTOCOL_VERSION = struct.pack(">H", 1)
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
        mac_gen = HMAC(Secret.PSK)
        s.sendall(mac_gen.hmac(b"client_auth"+PROTOCOL_VERSION + server_id+client_id + A + B))

        mac_rcv = s.recv(32)
        if mac_rcv != mac_gen.hmac( b"server_auth"+PROTOCOL_VERSION + server_id+client_id + A + B):
            print("Server hasn't been authenticated. Closing connection.")
            s.close()
            return
        print("Server Authenticated")
        channel= generate_channel(Secret.PSK,shared_secret,PROTOCOL_VERSION,client_id,s,server_id)
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
    run_client()