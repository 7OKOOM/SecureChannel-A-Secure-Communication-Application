import os
import socket

from hdkf import HKDF
from hmac import HMAC
import threading
from X25519 import X25519
from secret import Secret
from secure_channel import SecureChannel

PROTOCOL_VERSION = b"\x00\x01"
server_id        = b"server"

def receiver(sock, channel: SecureChannel, client_id):
    while not sock._closed:
        msg_type,plaintext,sender_id = channel.receive_message()
        if sender_id != client_id:
            print("Error")
            break
            ## this is only for error in code if exists, since the tag is blinded with the creation of MAC, if the id is different it will return an error
        print("HIM: "+plaintext.decode())
        if msg_type ==2:
            print("closing Connection")
            sock.close()
            return


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
            print("Client Authenticated")
            mixer = HKDF()
            conn.sendall(mac_gen.hmac(Secret.PSK, b"server_auth"+PROTOCOL_VERSION + server_id+client_id + A + B))

            key = mixer.hkdf(Secret.PSK,shared_secret,PROTOCOL_VERSION+b" PhaseB keys and nonces",88)

            key_server_to_client = key[:32]
            key_client_to_server = key[32:64]
            nonce_server_to_client = key[64:76]
            nonce_client_to_server = key[76:]
            channel = SecureChannel(conn,key_server_to_client,key_client_to_server,nonce_server_to_client,nonce_client_to_server,PROTOCOL_VERSION)
            t = threading.Thread(target=receiver, args=(conn, channel, client_id))
            t.start()
            while not conn._closed:
                message= input()
                if not conn._closed: channel.send_message(1,message.encode(),server_id)

                # try:
                #     type = int(input("What Action do you want?\n1.Send a message\n2.quit\n"))
                #     if  type ==1:
                #         message= input("Insert your message: ")
                #         if not conn._closed: channel.send_message(1,message.encode(),server_id)
                #         else:
                #             print("channel has been closed. closing connection.")
                #             return
                #     elif type ==2:
                #         channel.send_message(2,b"",server_id)
                #         if not conn._closed: conn.close()
                #         return
                #     else:
                #         print("Invalid input.")
                # except:
                #     print("Invalid input.")



if __name__ == "__main__":
    run_server()