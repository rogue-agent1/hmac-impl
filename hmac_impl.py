#!/usr/bin/env python3
"""hmac_impl - HMAC implementation with SHA-256."""
import sys, hashlib

def hmac_sha256(key, message):
    if isinstance(key, str): key = key.encode()
    if isinstance(message, str): message = message.encode()
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block_size, b"\x00")
    o_key_pad = bytes(b ^ 0x5C for b in key)
    i_key_pad = bytes(b ^ 0x36 for b in key)
    inner = hashlib.sha256(i_key_pad + message).digest()
    return hashlib.sha256(o_key_pad + inner).hexdigest()

def verify_hmac(key, message, expected):
    computed = hmac_sha256(key, message)
    if len(computed) != len(expected):
        return False
    result = 0
    for a, b in zip(computed, expected):
        result |= ord(a) ^ ord(b)
    return result == 0

def pbkdf2_sha256(password, salt, iterations=1000, dk_len=32):
    if isinstance(password, str): password = password.encode()
    if isinstance(salt, str): salt = salt.encode()
    import hmac as _hmac
    dk = b""
    block = 1
    while len(dk) < dk_len:
        u = _hmac.new(password, salt + block.to_bytes(4, "big"), hashlib.sha256).digest()
        result = u
        for _ in range(iterations - 1):
            u = _hmac.new(password, u, hashlib.sha256).digest()
            result = bytes(a ^ b for a, b in zip(result, u))
        dk += result
        block += 1
    return dk[:dk_len].hex()

def test():
    mac = hmac_sha256("secret", "hello")
    assert len(mac) == 64
    mac2 = hmac_sha256("secret", "hello")
    assert mac == mac2
    mac3 = hmac_sha256("different", "hello")
    assert mac3 != mac
    mac4 = hmac_sha256("secret", "world")
    assert mac4 != mac
    assert verify_hmac("secret", "hello", mac)
    assert not verify_hmac("secret", "hello", mac3)
    assert not verify_hmac("wrong", "hello", mac)
    dk = pbkdf2_sha256("password", "salt", iterations=100)
    assert len(dk) == 64
    dk2 = pbkdf2_sha256("password", "salt", iterations=100)
    assert dk == dk2
    dk3 = pbkdf2_sha256("password", "different_salt", iterations=100)
    assert dk3 != dk
    long_key = "a" * 100
    mac5 = hmac_sha256(long_key, "test")
    assert len(mac5) == 64
    print("All tests passed!")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("hmac_impl: HMAC implementation. Use --test")
