import struct

from chacha20_poly1305_AEAD import ChaCha20Poly1305

class SecureChannel:
    def __init__(self, sock, send_key, recv_key, send_nonce, recv_nonce,version):
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

    def send_message(self, msg_type, plaintext, sender_id):
        if self.closed:
            raise Exception("Channel is closed")

        seq = self.send_seq
        nonce = self._make_nonce(self.send_nonce, seq)

        # Build AAD (plaintext header)
        aad = self.version          # version
        aad += struct.pack('B', msg_type)        # 1 byte
        aad += struct.pack('<Q', seq)            # 8 bytes
        aad += struct.pack('B', len(sender_id)) + sender_id

        # Encrypt
        ciphertext, tag = self.send_cipher.encrypt(nonce, plaintext, aad)

        # Frame: [aad_len: 4 bytes][aad][ct_len: 4 bytes][ciphertext][tag: 16 bytes]
        frame = struct.pack('>I', len(aad)) + aad
        frame += struct.pack('>I', len(ciphertext)) + ciphertext
        frame += tag

        self.sock.sendall(frame)
        self.send_seq += 1

    def receive_message(self):
        if self.closed:
            raise Exception("Channel is closed")

        # Read AAD
        aad_len = struct.unpack('>I', self._read_exact(4))[0]
        aad = self._read_exact(aad_len)

        # Read ciphertext
        ct_len = struct.unpack('>I', self._read_exact(4))[0]
        ciphertext = self._read_exact(ct_len)

        # Read tag
        tag = self._read_exact(16)

        # Parse AAD
        version = aad[0:2]
        msg_type = aad[2]
        seq = struct.unpack('<Q', aad[3:11])[0]
        sender_id_len = aad[11]
        sender_id = aad[12:12 + sender_id_len]

        if version != self.version:
            raise Exception("Version mismatch in message")

        # Replay / reorder check
        if seq != self.recv_seq:
            raise Exception(f"Replay or reorder: expected {self.recv_seq}, got {seq}")

        # Decrypt and verify
        nonce = self._make_nonce(self.recv_nonce, seq)
        plaintext = self.recv_cipher.decrypt(nonce, ciphertext, tag, aad)

        self.recv_seq += 1
        return msg_type, plaintext, sender_id

    def close(self):
        self.closed = True
        self.sock.close()