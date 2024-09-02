import secrets
import base64
import re

def xorTuple(x):
	return x[0]^x[1]

def encrypt(plainText, padLength):
	bytesPlainText = plainText.encode("utf-8")
	return encryptBytes(bytesPlainText, padLength)

def encryptBytes(bytesPlainText, padLength):
	if len(bytesPlainText) > padLength:
		raise Exception("PlainText string contains more bytes than desired padded length")

	paddedBytesPlainText = bytesPlainText.ljust(padLength, b" ")
	bytesRandom = secrets.token_bytes(len(paddedBytesPlainText))

	tuples = zip(paddedBytesPlainText, bytesRandom)
	encrypted = bytes(map(xorTuple, tuples))

	return [bytesRandom, encrypted]

def decryptBytes(encrypted1, encrypted2):
	if len(encrypted1) != len(encrypted2):
		raise Exception("Inputs must be of the same length!")

	tuples = zip(encrypted1, encrypted2)

	return bytes(map(xorTuple, tuples))

def decrypt(encrypted1, encrypted2):
	return decryptBytes(encrypted1, encrypted2).decode("utf-8")

def encodeForWritingToPaper(input):
	return re.sub(r'(.{4})', r'\1 ', base64.b32encode(input).decode("utf-8")).strip()

def decodeAfterReadingFromPaper(input):
	return base64.b32decode(re.sub(r' ', '', input), casefold=True, map01='I')