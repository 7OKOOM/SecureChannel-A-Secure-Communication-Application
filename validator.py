from hdkf import HKDF
from hmac import HMAC

from sha256 import SHA256
from chacha20_poly1305_AEAD import ChaCha20Poly1305
def p(input_data,is_pass):
    if is_pass:
        print(f"PASS: {input_data[:10]}...")
    else:
        print(f"FAIL: {input_data[:10]}...")

def validate_vectors_chacha20_poly1305():
    # vector taken from the following link
    # https://datatracker.ietf.org/doc/html/rfc8439
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
    print("Validating ChaCha20-Poly1305 AEAD")
    for key, nonce, aad, plaintext, expected_ct, expected_tag in test_cases:
        cipher = ChaCha20Poly1305(key)
        ciphertext, tag = cipher.encrypt(nonce, plaintext, aad)
        p(plaintext,ciphertext.hex() == expected_ct and tag.hex() == expected_tag)

#validate_vectors_chacha20_poly1305()



def validate_vectors_sh256():

    #vectors taken from the following link
    #https://datatracker.ietf.org/doc/html/rfc4634
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (b"a" * 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    ]
    print("Validating SHA256")
    hasher = SHA256()

    for input_data, expected in test_cases:
        result = hasher.hash(input_data).hex()
        p(input_data,result == expected)
# validate_vectors_sh256()


def validate_vectors_hmac():

    #vectors taken from the following link
    #https://datatracker.ietf.org/doc/html/rfc4231
    test_cases = [
        (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (b"\xaa" * 20, b"\xdd" * 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"), b"\xcd" * 50, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (b"\x0c" * 20, b"Test With Truncation", "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5"),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (b"\xaa" * 131, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
    ]
    print("Validating HMAC")
    mac = HMAC()
    for key, input_data, expected in test_cases:
        result = mac.hmac(key,input_data).hex()
        p(input_data,result == expected)
# validate_vectors_hmac()

def validate_vectors_hdkf():

    #vectors taken from the following link
    #https://datatracker.ietf.org/doc/html/rfc5869
    test_cases = [
        (bytes.fromhex("000102030405060708090a0b0c"), b"\x0b" * 22, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
        (bytes.fromhex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
         bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), 82, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
        (b"", b"\x0b" * 22, b"", 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    ]
    print("Validating HDKF")
    hkdf = HKDF()
    for salt, ikm, info,length,expected in test_cases:
        result = hkdf.hkdf(salt,ikm,info,length).hex()
        p(info,result == expected)
validate_vectors_hdkf()
