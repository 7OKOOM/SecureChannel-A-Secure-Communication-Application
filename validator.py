from sha256 import SHA256

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