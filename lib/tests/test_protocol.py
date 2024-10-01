import unittest
from unittest.mock import call, patch

from lib.exceptions import ValidationError
from lib.protocol import encodeBase32, decodeAndValidateB32, decryptAndDecodeUtf8, utf8EncodeAndEncrypt

class TestEncryption(unittest.TestCase):
	@patch('lib.protocol.encryptBytes')
	def test_encrypt(self, mock_encrypt_bytes):
		mock_encrypt_bytes.side_effect = [[b'12345', b'98765'], [b'asdfe', b'zyxwv'], [b'hjklm', b'qwerty']]

		result = utf8EncodeAndEncrypt("abc", 5, 4)
		
		self.assertEqual(mock_encrypt_bytes.mock_calls, [call(b'abc', 5), call(b'98765', 5), call(b'zyxwv', 5)])
		self.assertEqual(result, [b'12345', b'asdfe', b'hjklm', b'qwerty'])

	@patch('lib.protocol.decryptBytes')
	def test_decrypt(self, mock_decrypt_bytes):
		mock_decrypt_bytes.side_effect = [b'zyxwv', b'98765', b'abc  ']

		result = decryptAndDecodeUtf8([b'12345', b'asdfe', b'hjklm', b'qwerty'], False)
		
		self.assertEqual(mock_decrypt_bytes.mock_calls, [call(b'12345', b'asdfe'), call(b'zyxwv', b'hjklm'), call(b'98765', b'qwerty')])
		self.assertEqual(result, "abc  ")

	@patch('lib.protocol.decryptBytes')
	def test_decryptEncodingFailure(self, mock_decrypt_bytes):
		mock_decrypt_bytes.return_value = b'ab\xFF  '

		with self.assertRaises(UnicodeDecodeError):
			decryptAndDecodeUtf8([b'12345', b'asdfe'], False)

		result = decryptAndDecodeUtf8([b'12345', b'asdfe'], True)
		self.assertEqual(result, "ab�  ")


class TestEncoding(unittest.TestCase):
	def test_encodeBase32(self):
		input = [b"The quick brown fox", b"jumps over the lazy"]

		result = encodeBase32(input)

		self.assertEqual(result, ["KRUG KIDR OVUW G2ZA MJZG 653O EBTG 66A=", "NJ2W 24DT EBXX MZLS EB2G QZJA NRQX U6I="])

	def test_decodeAndValidateB32(self):
		input1 = "KRUG KIDR OVUW G2ZA MJZG 653O EBTG 66A="
		input2 = "NJ2W 24DT EBXX MZLS EB2G QZJA NRQX U6I="
		input3 = "MRXW OLQ="

		result1 = decodeAndValidateB32(input1, [])
		self.assertEqual(result1, [b"The quick brown fox"])

		result2 = decodeAndValidateB32(input2, result1)
		self.assertEqual(result2, [b"The quick brown fox", b"jumps over the lazy"])

		with self.assertRaises(ValidationError):
			decodeAndValidateB32(input3, result2)