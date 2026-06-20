from sha256 import SHA256
from chacha20_poly1305_AEAD import ChaCha20Poly1305

def validate_vectors_chacha20poly1305():
    # vector taken from the following link
    # https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    test_cases = [
        (
            bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            bytes.fromhex("070000004041424344454647"),
            bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d"
            "63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b"
            "3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d"
            "7bc3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691",
        ),
    ]
    for key, nonce, aad, plaintext, expected_ct, expected_tag in test_cases:
        cipher = ChaCha20Poly1305(key)
        ciphertext, tag = cipher.encrypt(nonce, plaintext, aad)
        if ciphertext.hex() == expected_ct and tag.hex() == expected_tag:
            print(f"PASS: {plaintext[:10]}...")
        else:
            print(f"FAIL: {plaintext[:10]}...")

validate_vectors_chacha20poly1305()



def validate_vectors_sh256():

    #vectors taken from the following link
    #https://datatracker.ietf.org/doc/html/rfc4634#section-8.4
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (b"a" * 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    ]
    for input_data, expected in test_cases:
        hasher = SHA256()
        result = hasher.hash(input_data).hex()
        if result == expected:
            print(f"PASS: {input_data[:10]}...")
        else:
            print(f"FAIL: {input_data[:10]}...")
            print(f"   Expected: {expected}")
            print(f"   Got:      {result}")
validate_vectors_sh256()
