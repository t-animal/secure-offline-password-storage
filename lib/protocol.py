import base64
import re

from .exceptions import PreconditionError, ValidationError
from .primitives import encryptBytes, decryptBytes

def utf8EncodeAndEncrypt(secret, paddedLength, desiredOutputCount):
    if desiredOutputCount < 2:
        raise PreconditionError(f"Cannot produce less than two output strings ({desiredOutputCount} requested)")

    secretAsBytes = secret.encode("utf-8")
    encryptedBytes = encryptBytes(secretAsBytes, paddedLength)

    while len(encryptedBytes) < desiredOutputCount:
        newSecret = encryptedBytes.pop()

        encryptedBytes = encryptedBytes + encryptBytes(newSecret, paddedLength)

    return encryptedBytes

def encodeBase32(encryptedBytes):
    encryptedBytesAsBase32 = map(_encodeB32, encryptedBytes)

    return list(encryptedBytesAsBase32)

def decodeAndValidateB32(encryptedBytesAsBase32, previouslyDecoded):
    encrytedBytes = _decodeB32(encryptedBytesAsBase32)

    if len(previouslyDecoded) > 0 and len(encrytedBytes) != len(previouslyDecoded[0]):
        raise ValidationError("Length of new input doesn't match existing inputs' lengths")

    return previouslyDecoded + [encrytedBytes]

def decryptAndDecodeUtf8(encrypted, ignoreUtf8EncodingErrors):
    if len(encrypted) < 2:
        raise PreconditionError(f"Cannot decrypt less than two encrypted strings ({len(encrypted)} passed)")

    decrypted = decryptBytes(encrypted[0], encrypted[1])

    for encryptedRestBytes in encrypted[2:]:
        decrypted = decryptBytes(decrypted, encryptedRestBytes)

    return decrypted.decode("utf-8", "replace" if ignoreUtf8EncodingErrors else "strict")

def _encodeB32(input):
    return re.sub(r'(.{4})', r'\1 ', base64.b32encode(input).decode("utf-8")).strip()

def _decodeB32(input):
    return base64.b32decode(re.sub(r' ', '', input), casefold=True, map01='I')
