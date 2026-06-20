import math

from hmac import HMAC

class HKDF:
    def extract(self,salt: bytes, ikm: bytes) -> bytes:
        if not salt:
            salt = b'\x00' * 32
        mac = HMAC()
        prk = mac.hmac(salt, ikm)
        return prk

    def expand(self, prk:bytes, info:bytes, length:int):
        t = [b'']
        mac = HMAC()
        for i in range (math.ceil(length / 32)):
            t.append(mac.hmac(prk,t[i]+info+ bytes([i+1]) ))
        return b''.join(t)[:length]

    def hkdf(self, salt: bytes, ikm: bytes, info: bytes ,length:int):
        prk = self.extract(salt, ikm)
        return self.expand(prk, info, length)



