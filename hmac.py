from sha256 import SHA256

class HMAC:
    def __init__(self):
        self.B = 64
        self.L = 32
        self.ipad = b'\x36'*self.B
        self.opad = b'\x5c'*self.B
    def hmac(self,key:bytes,text:bytes):
        hasher = SHA256()
        if len(key)>self.B:
            key = hasher.hash(key)
        if len(key)<self.B:
            key = key + b'\x00'*(self.B-len(key))
        inner = bytes(key[i] ^ self.ipad[i] for i in range(64)) + text
        outer = bytes(key[i] ^ self.opad[i] for i in range(64)) + hasher.hash(inner)
        return hasher.hash(outer)
