import unittest
from unittest.mock import patch
import secrets

from src.exceptions import PreconditionError
from src.primitives import decryptBytes, encryptBytes, xorTuple

class TestEncryption(unittest.TestCase):
	def test_xorTuple(self):
		xored0From00 = xorTuple((0,0))
		xored0From11 = xorTuple((1,1))
		xored3From12 = xorTuple((1,2))
		xored3From21 = xorTuple((2,1))

		self.assertEqual(xored0From00, 0)
		self.assertEqual(xored0From11, 0)
		self.assertEqual(xored3From12, 3)
		self.assertEqual(xored3From21, 3)

	@patch('secrets.token_bytes')
	def test_encryptMockedSecret(self, mock_token_bytes):
		mock_token_bytes.return_value = b'abcde'

		encrypted = encryptBytes(b"abcde", 5)
		self.assertEqual(encrypted, (b'abcde', bytes([0]*5)))

		encrypted = encryptBytes(b"bcdef", 5)
		self.assertEqual(encrypted, (b'abcde', bytes([ord('a')^ord('b'), ord('b')^ord('c'), ord('c')^ord('d'), ord('d')^ord('e'), ord('e')^ord('f')])))

		encrypted = encryptBytes(b"abc", 5)
		self.assertEqual(encrypted, (b'abcde', bytes([0]*3 + [ord('D'), ord('E')]))) # xor with ' ' shifts cae

	def test_encrypt(self):
		testInput = b"123"

		encrypted = encryptBytes(testInput, 3)

		self.assertEqual(bytes(map(xorTuple, zip(*encrypted))), testInput)

	def test_padding(self):
		testInput = b"123"

		encrypted = encryptBytes(testInput, 10)

		self.assertEqual(bytes(map(xorTuple, zip(*encrypted))), testInput + b" " * 7)

	def test_tooShortPadding(self):
		encryptBytes(b"12345", 5)

		with self.assertRaises(PreconditionError):
			encryptBytes(b"123456", 5)

		with self.assertRaises(PreconditionError):
			# ä is encoded as two bytes
			encryptBytes("1234ä".encode("utf-8"), 5)

	def test_encryptDecrypt(self):
		testInput = b"123"

		decrypted = decryptBytes(*encryptBytes(testInput, 3))

		self.assertEqual(decrypted, testInput)

	def test_decryptInequalLength(self):
		with self.assertRaises(PreconditionError):
			decryptBytes(b'123', b'12')
