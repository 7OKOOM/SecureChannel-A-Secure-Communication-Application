import math

from hmac import HMAC

class HKDF:
    def extract(self,salt: bytes, ikm: bytes) -> bytes:
        if not salt:
            salt = b'\x00' * 32
        mac = HMAC(salt)
        prk = mac.hmac(ikm)
        return prk

    def expand(self, prk:bytes, info:bytes, length:int):
        t = [b'']
        mac = HMAC(prk)
        for i in range (math.ceil(length / 32)):
            t.append(mac.hmac(t[i]+info+ bytes([i+1]) ))
        return b''.join(t)[:length]

    def hkdf(self, salt: bytes, ikm: bytes, info: bytes ,length:int):
        prk = self.extract(salt, ikm)
        return self.expand(prk, info, length)



