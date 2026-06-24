import os

from X25519 import X25519

gen = X25519()
a = bytearray(os.urandom(32))
A = gen.generate_public_key(a)


b = bytearray(os.urandom(32))
B = gen.generate_public_key(b)

print(gen.compute_shared_secret(a,B))
print(gen.compute_shared_secret(b,A))

