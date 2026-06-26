import socket

from chacha20_poly1305_AEAD import ChaCha20Poly1305
from hdkf import HKDF
from hmac import HMAC
import threading
from X25519 import X25519
import os

from secret import Secret
from secure_channel import SecureChannel

PROTOCOL_VERSION = b"\x00\x01"
client_id        = b"client"

def worker(sock, channel: SecureChannel, server_id):
    while not sock._closed:
        msg_type,plaintext,sender_id = channel.receive_message()
        if sender_id != server_id:
            print("Error")
            break
            ## this is only for error in code if exists, since the tag is blinded with the creation of MAC, if the id is different it will return an error
        print("HIM: "+plaintext.decode())
        if msg_type ==2:
            print("closing Connection")
            sock.close()
            return
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
        print("Server Authenticated")
        mixer = HKDF()
        key = mixer.hkdf(Secret.PSK,shared_secret,PROTOCOL_VERSION+b" PhaseB keys and nonces",88)

        key_server_to_client = key[:32]
        key_client_to_server = key[32:64]
        nonce_server_to_client = key[64:76]
        nonce_client_to_server = key[76:]

        channel = SecureChannel(s,key_client_to_server,key_server_to_client,nonce_client_to_server,nonce_server_to_client,PROTOCOL_VERSION)
        t = threading.Thread(target=worker, args=(s,channel, server_id))
        t.start()
        while not s._closed:
            message= input()
            if not s._closed: channel.send_message(1,message.encode(),client_id)


            # try:
            #     type = int(input("What Action do you want?\n1.Send a message\n2.quit\n"))
            #     if  type ==1:
            #         message= input("Insert your message: ")
            #         if not s._closed: channel.send_message(1,message.encode(),client_id)
            #         else:
            #             print("channel has been closed. closing connection.")
            #             return
            #     elif type ==2:
            #         channel.send_message(2,b"",client_id)
            #         if not s._closed: s.close()
            #         s.close()
            #         return
            #     else:
            #         print("Invalid input.")
            # except:
            #     print("Invalid input.")


if __name__ == "__main__":
    run_client()