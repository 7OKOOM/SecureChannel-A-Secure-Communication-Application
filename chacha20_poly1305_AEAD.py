import struct

class ChaCha20:

    def __init__(self, key, nonce):
        assert len(key) == 32
        assert len(nonce) == 12
        self.key = key
        self.nonce = nonce

    @staticmethod
    def _rotl32(v, c):
        return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

    @classmethod
    def _quarter_round(cls, x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] ^= x[a]
        x[d] = cls._rotl32(x[d], 16)

        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] ^= x[c]
        x[b] = cls._rotl32(x[b], 12)

        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] ^= x[a]
        x[d] = cls._rotl32(x[d], 8)

        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] ^= x[c]
        x[b] = cls._rotl32(x[b], 7)

    def block(self, counter):
        """Generate one 64-byte keystream block for the given counter value."""
        constants = struct.unpack('<4I', b'expand 32-byte k')
        key_words = struct.unpack('<8I', self.key)
        counter_bytes = struct.pack('<I', counter)
        counter_nonce = struct.unpack('<4I', counter_bytes + self.nonce)
        state = list(constants) + list(key_words) + list(counter_nonce)
        working_state = state.copy()

        for _ in range(10):
            self._quarter_round(working_state, 0, 4, 8, 12)
            self._quarter_round(working_state, 1, 5, 9, 13)
            self._quarter_round(working_state, 2, 6, 10, 14)
            self._quarter_round(working_state, 3, 7, 11, 15)
            self._quarter_round(working_state, 0, 5, 10, 15)
            self._quarter_round(working_state, 1, 6, 11, 12)
            self._quarter_round(working_state, 2, 7, 8, 13)
            self._quarter_round(working_state, 3, 4, 9, 14)

        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

        return struct.pack('<16I', *working_state)

    def encrypt(self, data, counter=1):
        """XOR data with the keystream starting at `counter`. Symmetric: also decrypts."""
        output = bytearray()
        for i in range(0, len(data), 64):
            keystream = self.block(counter)
            block = data[i:i + 64]
            for j in range(len(block)):
                output.append(block[j] ^ keystream[j])
            counter += 1
        return bytes(output)


class Poly1305:
   
    def __init__(self, key):
        assert len(key) == 32
        self.r = int.from_bytes(key[:16], byteorder='little') & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
        self.s = int.from_bytes(key[16:], byteorder='little')

    @staticmethod
    def pad16(data):
        padding_length = (16 - (len(data) % 16)) % 16
        return b'\x00' * padding_length

    def mac(self, message):
        p = 2 ** 130 - 5
        acc = 0
        for i in range(0, len(message), 16):
            block = message[i:i + 16]
            n = int.from_bytes(block + b'\x01', byteorder='little')
            acc = (acc + n) * self.r % p
        acc = (acc + self.s) % (2 ** 128)
        return acc.to_bytes(16, byteorder='little')


class ChaCha20Poly1305:
   
    def __init__(self, key):
        assert len(key) == 32
        self.key = key

    def encrypt(self, nonce, plaintext, associated_data=b''):
        assert len(nonce) == 12

        cipher = ChaCha20(self.key, nonce)
        poly_key = cipher.block(0)[:32]
        ciphertext = cipher.encrypt(plaintext, counter=1)

        mac_data = bytearray()
        mac_data += associated_data
        mac_data += Poly1305.pad16(associated_data)
        mac_data += ciphertext
        mac_data += Poly1305.pad16(ciphertext)
        mac_data += struct.pack('<Q', len(associated_data))
        mac_data += struct.pack('<Q', len(ciphertext))

        tag = Poly1305(poly_key).mac(mac_data)

        return ciphertext, tag
