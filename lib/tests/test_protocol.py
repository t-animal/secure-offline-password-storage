import copy
import unittest
from unittest.mock import ANY, call, patch

from lib.exceptions import PreconditionError, ValidationError
from lib.protocol import DecryptionProtocol, EncryptionProtocol

theQuickBrownFoxB32="KRUG KIDR OVUW G2ZA MJZG 653O EBTG 66A="
jumpsOverTheLazyDogB32="NJ2W 24DT EBXX MZLS EB2G QZJA NRQX U6I="

class TestEncryptProtocol(unittest.TestCase):

	def test_outputCount(self):
		protocol = EncryptionProtocol(paddedLength = 10, desiredOutputCount = 7)

		encrypted = protocol.encrypt("asdf")
		
		self.assertEqual(len(encrypted), 7)
		with self.assertRaises(PreconditionError):
			EncryptionProtocol(paddedLength = 10, desiredOutputCount = 1)

	def test_padding(self):
		protocol = EncryptionProtocol(paddedLength = 10, desiredOutputCount = 2)

		encryptedAscii = protocol.encrypt("123")
		encryptedUtf8 = protocol.encrypt("äbc")

		self.assertEqual(len(encryptedAscii[0]), 10)
		self.assertEqual(len(encryptedAscii[1]), 10)
		self.assertEqual(len(encryptedUtf8[0]), 10)
		self.assertEqual(len(encryptedUtf8[1]), 10)

	@patch('lib.protocol.encryptBytes')
	def test_encrypt(self, mock_encryptBytes):
		mockEncryptResult=[[b'12345', b'98765'], [b'asdfe', b'zyxwv'], [b'hjklm', b'qwerty']]
		mock_encryptBytes.side_effect = copy.deepcopy(mockEncryptResult)

		protocol = EncryptionProtocol(paddedLength = 5, desiredOutputCount = 4)

		result = protocol.encrypt("abc")
		
		mock_encryptBytes.assert_has_calls([
			call(b'abc', 5),
			call(mockEncryptResult[0][1], 5),
			call(mockEncryptResult[1][1], 5)
		])
		self.assertEqual(result, [mockEncryptResult[0][0], mockEncryptResult[1][0], *mockEncryptResult[2]])

	def test_encodeBase32(self):
		protocol = EncryptionProtocol(paddedLength = 5, desiredOutputCount = 4)
		input = [b"The quick brown fox", b"jumps over the lazy"]

		result = protocol.encodeBase32(input)

		self.assertEqual(result, [theQuickBrownFoxB32, jumpsOverTheLazyDogB32])

class TestDecryptProtocol(unittest.TestCase):

	@patch('lib.protocol.decryptBytes')
	def test_decrypt(self, mock_decryptBytes):
		protocol = DecryptionProtocol()

		mockEncryptResult = [b'zyxwv', b'98765', b'abc  ']
		mock_decryptBytes.side_effect = mockEncryptResult

		protocol.decodeBase32AndStore('KRUG KIDR')
		protocol.decodeBase32AndStore('OVUW G2ZA')
		protocol.decodeBase32AndStore('MJZG 653O')
		protocol.decodeBase32AndStore('EBTG 66BA')
		result = protocol.decrypt(ignoreUtf8EncodingErrors = False)
		
		mock_decryptBytes.assert_has_calls([
			call(b'The q', b'uick '),
			call(mockEncryptResult[0], b'brown'),
			call(mockEncryptResult[1], b' fox ')
		])
		self.assertEqual(result, "abc  ")

	def test_decryptTooFewInputs(self):
		protocol = DecryptionProtocol()
		protocol.decodeBase32AndStore('KRUG KIDR')

		with self.assertRaises(PreconditionError):
			protocol.decrypt(ignoreUtf8EncodingErrors = False)

	def test_decodeBase32(self):
		protocol = DecryptionProtocol()

		input1 = theQuickBrownFoxB32
		input2 = jumpsOverTheLazyDogB32
		input3 = "MRXW OLQ="

		protocol.decodeBase32AndStore(input1)
		self.assertEqual(protocol.encryptedBytes[0], b"The quick brown fox")

		protocol.decodeBase32AndStore(input2)
		self.assertEqual(protocol.encryptedBytes[1], b"jumps over the lazy")

		with self.assertRaises(ValidationError):
			protocol.decodeBase32AndStore(input3)

	@patch('lib.protocol.decryptBytes')
	def test_decryptEncodingFailure(self, mock_decryptBytes):
		protocol = DecryptionProtocol()
		protocol.decodeBase32AndStore("KRUG KIDR")
		protocol.decodeBase32AndStore("NJ2W 24DT")

		mock_decryptBytes.return_value = b'ab\xFF  '

		with self.assertRaises(UnicodeDecodeError):
			protocol.decrypt(ignoreUtf8EncodingErrors = False)

		result = protocol.decrypt(ignoreUtf8EncodingErrors = True)
		self.assertEqual(result, "ab�  ")