import socket

def run_server(host='127.0.0.1', port=65432):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # PHASE A: Handshake (Implement X25519 + HMAC Authentication)
            # TODO: Perform key exchange and verify PSK-based transcript

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