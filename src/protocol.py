"""Classes for encrypting and decrypting strings"""
import base64
import re

from src.exceptions import PreconditionError, ValidationError
from src.primitives import encrypt_bytes, decrypt_bytes

class EncryptionProtocol:
    """
    Protocol class for padding and encrypting a string a number of times so 
    that it can be stored safely on paper. The padding length and number 
    of times to encrypt can be specified in the constructor. Then, a string
    can be encrypted using encrypt and encoded using base32 for writing it 
    to paper
    """
    def __init__(self, padded_length: int, desired_output_count: int):
        if desired_output_count < 2:
            raise PreconditionError(
                f"Cannot produce less than two output strings ({desired_output_count} requested)"
            )

        self.padded_length = padded_length
        self.desired_output_count = desired_output_count

    def encrypt(self, secret: str) -> list[bytes]:
        """
        Encrypts a secret string (after padding it) using one-time-pad as
        often as stated in the constructor and returns a list of the 
        employed secrets and the encrypted secret.
        """
        secret_as_bytes = secret.encode("utf-8")
        encrypted_bytes: list[bytes] = list(encrypt_bytes(secret_as_bytes, self.padded_length))

        while len(encrypted_bytes) < self.desired_output_count:
            new_secret = encrypted_bytes.pop()

            encrypted_bytes = encrypted_bytes + list(encrypt_bytes(new_secret, self.padded_length))

        return encrypted_bytes

    def encode_base32(self, encrypted_bytes: list[bytes]) -> list[str]:
        """Encodes each entry in a list of byte strings as base 32"""
        encrypted_bytes_as_base32 = map(_encode_b32, encrypted_bytes)

        return list(encrypted_bytes_as_base32)

class DecryptionProtocol:
    """
    Protocol class for decrypting strings that have been encrypted using the
    encryption protocol. First add all base32 strings using decode_base32_and_store
    and then decrypt them using decrypt
    """
    def __init__(self):
        self.encrypted_bytes: list[bytes] = []

    def decode_base32_and_store(self, encrypted_bytes_as_base32: str) -> None:
        """
        Validates that the given string is valid base 32 and then stores it internally for 
        decrypting. Throws ValidationError if the decoded byte string doesn't have the same
        length as the already stored strings
        """
        new_encrypted_bytes: bytes = _decode_b32(encrypted_bytes_as_base32)

        if len(self.encrypted_bytes) > 0 and \
            len(new_encrypted_bytes) != len(self.encrypted_bytes[0]):
            raise ValidationError("Length of new input doesn't match existing inputs' lengths")

        self.encrypted_bytes += [new_encrypted_bytes]

    def decrypt(self, ignore_utf8_encoding_errors: bool) -> str:
        """
        Decrypts the strings that have been added before using decode_base32_and_store. 
        Then it decodes the resulting bytes into a utf-8 string. If that fails, the input
        was likely incorrect. Then, the ignore_utf8_encoding_errors can be set to ignore
        the utf-8 encoding errors and replace the broken characters with a replacement
        character."""
        if len(self.encrypted_bytes) < 2:
            raise PreconditionError(
                "Cannot decrypt less than two encrypted strings" +
                f"({len(self.encrypted_bytes)} passed)"
            )

        decrypted = decrypt_bytes(self.encrypted_bytes[0], self.encrypted_bytes[1])

        for encrypted_rest_bytes in self.encrypted_bytes[2:]:
            decrypted = decrypt_bytes(decrypted, encrypted_rest_bytes)

        return decrypted.decode("utf-8", "replace" if ignore_utf8_encoding_errors else "strict")

def _encode_b32(byte_input: bytes) -> str:
    return re.sub(r'(.{4})', r'\1 ', base64.b32encode(byte_input).decode("utf-8")).strip()

def _decode_b32(string_input: str) -> bytes:
    return base64.b32decode(re.sub(r' ', '', string_input), casefold=True, map01='I')
