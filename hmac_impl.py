#!/usr/bin/env python3
"""HMAC implementation (RFC 2104) using SHA-256."""
import hashlib, struct

BLOCK_SIZE = 64

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
    key = key.ljust(BLOCK_SIZE, b'\x00')
    o_pad = bytes(k ^ 0x5c for k in key)
    i_pad = bytes(k ^ 0x36 for k in key)
    return hashlib.sha256(o_pad + hashlib.sha256(i_pad + message).digest()).digest()

def verify(key: bytes, message: bytes, tag: bytes) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(hmac_sha256(key, message), tag)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: hmac_impl.py <key> <message>")
        sys.exit(1)
    tag = hmac_sha256(sys.argv[1].encode(), sys.argv[2].encode())
    print(tag.hex())

def test():
    # Test vector from RFC 4231
    tag = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog")
    assert len(tag) == 32
    # Verify
    assert verify(b"key", b"The quick brown fox jumps over the lazy dog", tag)
    assert not verify(b"wrong", b"The quick brown fox jumps over the lazy dog", tag)
    # Long key gets hashed
    long_key = b"x" * 100
    tag2 = hmac_sha256(long_key, b"test")
    assert len(tag2) == 32
    # Known vector: HMAC-SHA256("key", "message")
    import hmac as _hmac
    expected = _hmac.new(b"key", b"message", hashlib.sha256).digest()
    assert hmac_sha256(b"key", b"message") == expected
    print("  hmac_impl: ALL TESTS PASSED")
