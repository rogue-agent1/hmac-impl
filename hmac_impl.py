#!/usr/bin/env python3
"""hmac_impl - HMAC implementation using SHA-256 (via hashlib)."""
import sys, hashlib

def hmac_sha256(key, message):
    if isinstance(key, str): key = key.encode()
    if isinstance(message, str): message = message.encode()
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block_size, b"\x00")
    o_key_pad = bytes(k ^ 0x5c for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    inner = hashlib.sha256(i_key_pad + message).digest()
    return hashlib.sha256(o_key_pad + inner).hexdigest()

def verify(key, message, expected_mac):
    computed = hmac_sha256(key, message)
    # Constant-time comparison
    if len(computed) != len(expected_mac): return False
    result = 0
    for a, b in zip(computed, expected_mac):
        result |= ord(a) ^ ord(b)
    return result == 0

def test():
    # RFC 4231 test vector 1
    key = b"\x0b" * 20
    msg = b"Hi There"
    mac = hmac_sha256(key, msg)
    assert mac == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    assert verify(key, msg, mac)
    assert not verify(key, b"tampered", mac)
    # Key longer than block size
    long_key = b"x" * 100
    mac2 = hmac_sha256(long_key, b"test")
    assert len(mac2) == 64
    assert verify(long_key, b"test", mac2)
    print("hmac_impl: all tests passed")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("Usage: hmac_impl.py --test")
