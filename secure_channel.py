import struct

from chacha20_poly1305_AEAD import ChaCha20Poly1305

class SecureChannel:
    def __init__(self, sock, send_key, recv_key, send_nonce, recv_nonce,version,sender):
        self.sock = sock
        self.version = version
        # Sending state
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.send_nonce = send_nonce      # 12 bytes from HKDF
        self.send_seq = 0

        # Receiving state
        self.recv_cipher = ChaCha20Poly1305(recv_key)
        self.recv_nonce = recv_nonce      # 12 bytes from HKDF
        self.recv_seq = 0
        self.sender=sender
        self.closed = False

    def _make_nonce(self, initial_nonce, seq_num):
        seq_bytes = struct.pack('<Q', seq_num).rjust(12, b'\x00')
        return bytes(a ^ b for a, b in zip(initial_nonce, seq_bytes))

    def _read_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Peer closed connection")
            data += chunk
        return data

    def send_message(self, msg_type, plaintext):
        if self.closed:
            raise Exception("Channel is closed")

        seq = self.send_seq
        nonce = self._make_nonce(self.send_nonce, seq)

        # Build AAD (plaintext header)
        aad = self.version          # version 2 bytes
        aad += struct.pack('B', msg_type)        # 1 byte
        aad += struct.pack('B', seq)            # 1 byte
        aad += struct.pack('B', len(self.sender)) + self.sender

        # Encrypt
        ciphertext, tag = self.send_cipher.encrypt(nonce, plaintext, aad)

        # Frame: [aad][ct_len: 4 bytes][ciphertext][tag: 16 bytes]
        frame =  aad
        frame += struct.pack('>I', len(ciphertext)) + ciphertext
        frame += tag
        self.sock.sendall(frame)
        self.send_seq += 1

    def receive_message(self):
        if self.closed:
            raise Exception("Channel is closed")
        aad1 = self._read_exact(5)# version 2 bytes, msg_type 1 byte, seq 1 byte , length is 1 byte : 2+1+1+1 =5.

        version = aad1[:2]
        if version != self.version:
            raise Exception("Version mismatch in message")
        msg_type = aad1[2:3]
        seq = struct.unpack('B', aad1[3:4])[0]
        # Replay / reorder check
        if seq != self.recv_seq:
            raise Exception(f"Replay or reorder: expected {self.recv_seq}, got {seq}")
        sender_len = aad1[4:]
        aad =  aad1 + self._read_exact(struct.unpack("B",sender_len)[0])

        # Read ciphertext
        ct_len = struct.unpack('>I', self._read_exact(4))[0]
        ciphertext = self._read_exact(ct_len)

        # Read tag
        tag = self._read_exact(16)

        # Decrypt and verify
        nonce = self._make_nonce(self.recv_nonce, seq)
        plaintext = self.recv_cipher.decrypt(nonce, ciphertext, tag, aad)

        self.recv_seq += 1
        return msg_type, plaintext

    def close(self):
        self.closed = True
        self.sock.close()