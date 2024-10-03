"""
Crypto primitives for encrypting and decrypting byte strings 
using randomly chosen one-time-pad
"""

import secrets

from .exceptions import PreconditionError


def xor_tuple(x: tuple[int, int]) -> int:
    """ Encrypts a single byte with another byte using XOR"""
    return x[0]^x[1]

def encrypt_bytes(bytes_plain_text: bytes, pad_length: int) -> tuple[bytes, bytes]:
    """ Encrypts a byte-string after padding it with whitespace to a certain length"""
    if len(bytes_plain_text) > pad_length:
        raise PreconditionError("PlainText string contains more bytes than desired padded length")

    padded_bytes_plain_text = bytes_plain_text.ljust(pad_length, b" ")
    bytes_random = secrets.token_bytes(len(padded_bytes_plain_text))

    tuples = zip(padded_bytes_plain_text, bytes_random)
    encrypted = bytes(map(xor_tuple, tuples))

    return (bytes_random, encrypted)

def decrypt_bytes(encrypted1: bytes, encrypted2: bytes) -> bytes:
    """ Decrypts two byte-strings using XOR and returns the resulting byte-string"""
    if len(encrypted1) != len(encrypted2):
        raise PreconditionError("Inputs must be of the same length!")

    tuples = zip(encrypted1, encrypted2)

    return bytes(map(xor_tuple, tuples))
