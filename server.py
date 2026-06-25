import os
import socket

from hdkf import HKDF
from hmac import HMAC

from X25519 import X25519
from secret import Secret
from secure_channel import SecureChannel

PROTOCOL_VERSION = b"\x00\x01"
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
            # PHASE A: Handshake (Implement X25519 + HMAC Authentication)
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
            mac_gen = HMAC()
            mac_rcv = conn.recv(32)
            if mac_rcv != mac_gen.hmac(Secret.PSK, b"client_auth"+PROTOCOL_VERSION + server_id+client_id + A + B):
                print("Client hasn't been authenticated. Closing connection.")
                conn.close()
                return
            print("mac received correctly!")
            mixer = HKDF()
            conn.sendall(mac_gen.hmac(Secret.PSK, b"server_auth"+PROTOCOL_VERSION + server_id+client_id + A + B))

            key = mixer.hkdf(Secret.PSK,shared_secret,PROTOCOL_VERSION+b" PhaseB keys and nonces",88)

            key_server_to_client = key[:32]
            key_client_to_server = key[32:64]
            nonce_server_to_client = key[64:76]
            nonce_client_to_server = key[76:]

            channel = SecureChannel(conn,key_server_to_client,key_client_to_server,nonce_server_to_client,nonce_client_to_server,PROTOCOL_VERSION)



            # PHASE B: Secure Messaging (ChaCha20-Poly1305)
            while True:
                message =channel.receive_message()
                msg_type = message[0]
                plaintext = message[1]
                sender_id = message[2]
                if sender_id != client_id:
                    print("Error")
                    break
                    ## this is only for error in code if exists, since the tag is blinded with the creation of MAC, if the id is different it will return an error
                print(f"Received (encrypted): {plaintext}")
                if msg_type ==2:
                    print("closing Connection")
                    conn.close()
                    return
if __name__ == "__main__":
    run_server()