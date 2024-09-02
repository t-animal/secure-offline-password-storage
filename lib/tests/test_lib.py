import unittest
from unittest.mock import patch
import secrets

from lib import decrypt, encrypt, xorTuple, encodeForWritingToPaper, decodeAfterReadingFromPaper

class TestEncryption(unittest.TestCase):
	def test_xorTuple(self):
		xored0From00 = xorTuple([0,0])
		xored0From11 = xorTuple([1,1])
		xored3From12 = xorTuple([1,2])
		xored3From21 = xorTuple([2,1])

		self.assertEqual(xored0From00, 0)
		self.assertEqual(xored0From11, 0)
		self.assertEqual(xored3From12, 3)
		self.assertEqual(xored3From21, 3)

	@patch('secrets.token_bytes')
	def test_encryptMockedSecret(self, mock_token_bytes):
		mock_token_bytes.return_value = b'abcde'

		encrypted = encrypt("abcde", 5)
		self.assertEqual(encrypted, [b'abcde', bytes([0]*5)])

		encrypted = encrypt("bcdef", 5)
		self.assertEqual(encrypted, [b'abcde', bytes([ord('a')^ord('b'), ord('b')^ord('c'), ord('c')^ord('d'), ord('d')^ord('e'), ord('e')^ord('f')])])

		encrypted = encrypt("abc", 5)
		self.assertEqual(encrypted, [b'abcde', bytes([0]*3 + [ord('D'), ord('E')])]) # xor with ' ' shifts case


	def test_encrypt(self):
		testInput = "123"

		encrypted = encrypt(testInput, 3)

		self.assertEqual(bytes(map(xorTuple, zip(*encrypted))).decode("utf-8"), testInput)

	def test_padding(self):
		testInput = "123"

		encrypted = encrypt(testInput, 10)

		self.assertEqual(bytes(map(xorTuple, zip(*encrypted))).decode("utf-8"), testInput + " " * 7)

	def test_tooShortPadding(self):
		encrypt("12345", 5)

		with self.assertRaises(Exception):
			encrypt("123456", 5)

		with self.assertRaises(Exception):
			# ä is encoded as two bytes
			encrypt("1234ä", 5)

	def test_encryptDecrypt(self):
		testInput = "123"

		decrypted = decrypt(*encrypt(testInput, 3))

		self.assertEqual(decrypted, testInput)

	def test_decryptInequalLength(self):
		with self.assertRaises(Exception):
			decrypt(b'123', b'12')



class TestEncoding(unittest.TestCase):
	def test_encoding(self):
		input = b"The quick brown fox"

		result = encodeForWritingToPaper(input)

		self.assertEqual(result, "KRUG KIDR OVUW G2ZA MJZG 653O EBTG 66A=")

	def test_decoding(self):
		input = "KRUG KIDR OVUW G2ZA MJZG 653O EBTG 66A="

		result = decodeAfterReadingFromPaper(input)

		self.assertEqual(result, b"The quick brown fox")