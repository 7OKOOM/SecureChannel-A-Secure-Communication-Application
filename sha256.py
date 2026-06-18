class SHA256:
    INITIAL_HASH_VALUES=[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    def __init__(self):
        self.H=list(SHA256.INITIAL_HASH_VALUES)
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    def add_padding(self,message:bytes):
        l = len(message)
        k = (55-l)%64
        l*=8
        l = l.to_bytes(8,'big')
        padded_message = message + b'\x80' + (b'\x00' * k) + l
        return padded_message

    def expand(self,message_padded:bytes):
        res = [int.from_bytes(message_padded[i:i+4], 'big') for i in range(0, len(message_padded), 4)]
        for i in range(16,64):
            res.append((self.sigma1_expansion(res[i - 2]) + res[i - 7] + self.sigma0_expansion(res[i - 15]) + res[i - 16]) & 0xFFFFFFFF)
        return res

    def rotate_right(self,x:int, n:int):return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def sigma0_expansion(self, x:int):return self.rotate_right(x, 7) ^ self.rotate_right(x, 18) ^ (x >> 3)

    def sigma1_expansion(self, x:int):return self.rotate_right(x, 17) ^ self.rotate_right(x, 19) ^ (x >> 10)

    def ch(self, x, y, z):return ((x & y) ^ ((~x) & z)) & 0xFFFFFFFF

    def maj(self, x, y, z):return ((x & y) ^ (x & z) ^ (y & z)) & 0xFFFFFFFF

    def sigma0_compression(self, x):return self.rotate_right(x, 2) ^ self.rotate_right(x, 13) ^ self.rotate_right(x, 22)

    def sigma1_compression(self, x):return self.rotate_right(x, 6) ^ self.rotate_right(x, 11) ^ self.rotate_right(x, 25)

    def compress(self, block: bytes):
        w = self.expand(block)

        a, b, c, d, e, f, g, h = self.H

        for i in range(64):
            T1 = (h + self.sigma1_compression(e) + self.ch(e, f, g) + self.K[i] + w[i]) & 0xFFFFFFFF
            T2 = (self.sigma0_compression(a) + self.maj(a, b, c)) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        # 4. Update the state
        self.H[0] = (self.H[0] + a) & 0xFFFFFFFF
        self.H[1] = (self.H[1] + b) & 0xFFFFFFFF
        self.H[2] = (self.H[2] + c) & 0xFFFFFFFF
        self.H[3] = (self.H[3] + d) & 0xFFFFFFFF
        self.H[4] = (self.H[4] + e) & 0xFFFFFFFF
        self.H[5] = (self.H[5] + f) & 0xFFFFFFFF
        self.H[6] = (self.H[6] + g) & 0xFFFFFFFF
        self.H[7] = (self.H[7] + h) & 0xFFFFFFFF

    def hash(self, message: bytes):
        self.H = list(self.INITIAL_HASH_VALUES)
        padded_message = self.add_padding(message)
        for i in range(0, len(padded_message), 64):
            block = padded_message[i : i + 64]
            self.compress(block)
        return b"".join(h.to_bytes(4, 'big') for h in self.H)




