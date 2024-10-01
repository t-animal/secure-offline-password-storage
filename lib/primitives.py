import secrets

from .exceptions import PreconditionError

def xorTuple(x):
	return x[0]^x[1]

def encryptBytes(bytesPlainText, padLength):
	if len(bytesPlainText) > padLength:
		raise PreconditionError("PlainText string contains more bytes than desired padded length")

	paddedBytesPlainText = bytesPlainText.ljust(padLength, b" ")
	bytesRandom = secrets.token_bytes(len(paddedBytesPlainText))

	tuples = zip(paddedBytesPlainText, bytesRandom)
	encrypted = bytes(map(xorTuple, tuples))

	return [bytesRandom, encrypted]

def decryptBytes(encrypted1, encrypted2):
	if len(encrypted1) != len(encrypted2):
		raise PreconditionError("Inputs must be of the same length!")

	tuples = zip(encrypted1, encrypted2)

	return bytes(map(xorTuple, tuples))
