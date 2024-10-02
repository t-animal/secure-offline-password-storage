import base64
import re

from .exceptions import PreconditionError, ValidationError
from .primitives import encryptBytes, decryptBytes

class EncryptionProtocol:
    def __init__(self, paddedLength, desiredOutputCount):
        if desiredOutputCount < 2:
            raise PreconditionError(f"Cannot produce less than two output strings ({desiredOutputCount} requested)")

        self.paddedLength = paddedLength
        self.desiredOutputCount = desiredOutputCount

    def encrypt(self, secret):
        secretAsBytes = secret.encode("utf-8")
        encryptedBytes = encryptBytes(secretAsBytes, self.paddedLength)

        while len(encryptedBytes) < self.desiredOutputCount:
            newSecret = encryptedBytes.pop()

            encryptedBytes = encryptedBytes + encryptBytes(newSecret, self.paddedLength)

        return encryptedBytes

    def encodeBase32(self, encryptedBytes):
        encryptedBytesAsBase32 = map(_encodeB32, encryptedBytes)

        return list(encryptedBytesAsBase32)

class DecryptionProtocol:
    def __init__(self):
        self.encryptedBytes = []

    def decodeBase32AndStore(self, encryptedBytesAsBase32):
        newEncryptedBytes = _decodeB32(encryptedBytesAsBase32)

        if len(self.encryptedBytes) > 0 and len(newEncryptedBytes) != len(self.encryptedBytes[0]):
            raise ValidationError("Length of new input doesn't match existing inputs' lengths")

        self.encryptedBytes += [newEncryptedBytes]

    def decrypt(self, ignoreUtf8EncodingErrors):
        if len(self.encryptedBytes) < 2:
            raise PreconditionError(f"Cannot decrypt less than two encrypted strings ({len(self.encryptedBytes)} passed)")

        decrypted = decryptBytes(self.encryptedBytes[0], self.encryptedBytes[1])

        for encryptedRestBytes in self.encryptedBytes[2:]:
            decrypted = decryptBytes(decrypted, encryptedRestBytes)

        return decrypted.decode("utf-8", "replace" if ignoreUtf8EncodingErrors else "strict")

def _encodeB32(input):
    return re.sub(r'(.{4})', r'\1 ', base64.b32encode(input).decode("utf-8")).strip()

def _decodeB32(input):
    return base64.b32decode(re.sub(r' ', '', input), casefold=True, map01='I')
