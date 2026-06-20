import struct

def rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def quarterRound(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = rotl32(x[d], 16)

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = rotl32(x[b], 12)

    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]
    x[d] = rotl32(x[d], 8)

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]
    x[b] = rotl32(x[b], 7)

def chacha20_block(key, counter, nonce):
    constants = struct.unpack('<4I', b'expand 32-byte k')
    key_words = struct.unpack('<8I', key)
    counter_bytes = struct.pack('<I', counter)      
    counter_nonce = struct.unpack('<4I', counter_bytes + nonce)  
    state = list(constants) + list(key_words) + list(counter_nonce)
    working_state = state.copy()

    for j in range(10):
        quarterRound(working_state, 0, 4, 8, 12)
        quarterRound(working_state, 1, 5, 9, 13)
        quarterRound(working_state, 2, 6, 10, 14)
        quarterRound(working_state, 3, 7, 11, 15)
        quarterRound(working_state, 0, 5, 10, 15)
        quarterRound(working_state, 1, 6, 11, 12)
        quarterRound(working_state, 2, 7, 8, 13)
        quarterRound(working_state, 3, 4, 9, 14)

    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

    return struct.pack('<16I', *working_state)


def poly1305_mac(key, message):
    r = int.from_bytes(key[:16], byteorder='little') & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], byteorder='little')
    p = 2**130 - 5
    acc = 0

    for i in range(0, len(message), 16):
        block = message[i:i+16]
        n = int.from_bytes(block + b'\x01', byteorder='little')
        acc = (acc + n) * r % p

    acc = (acc + s) % (2**128)
    return acc.to_bytes(16, byteorder='little')


def pad16(data):
    padding_length = (16 - (len(data) % 16)) % 16
    return b'\x00' * padding_length


def chacha20_aead_encrypt(key, nonce, plaintext, associated_data=b''):
    assert len(key) == 32
    assert len(nonce) == 12

    poly_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = bytearray()
    counter = 1
    for i in range(0, len(plaintext), 64):
        key_stream = chacha20_block(key, counter, nonce)
        block = plaintext[i:i+64]
        for j in range(len(block)):
            ciphertext.append(block[j] ^ key_stream[j])
        counter += 1
    ciphertext = bytes(ciphertext)

    mac_data = bytearray()
    mac_data += associated_data
    mac_data += pad16(associated_data)
    mac_data += ciphertext
    mac_data += pad16(ciphertext)
    mac_data += struct.pack('<Q', len(associated_data))
    mac_data += struct.pack('<Q', len(ciphertext))

    tag = poly1305_mac(poly_key, mac_data)

    return ciphertext, tag
