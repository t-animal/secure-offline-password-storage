"""Tests for protocol.py"""
import copy
import unittest
from unittest.mock import call, patch

from src.exceptions import PreconditionError, ValidationError
from src.protocol import DecryptionProtocol, EncryptionProtocol

THE_QUICK_BROWN_FOX_B32="KRUG KIDR OVUW G2ZA MJZG 653O EBTG 66A="
JUMPS_OVER_THE_LAZY_DOG_B32="NJ2W 24DT EBXX MZLS EB2G QZJA NRQX U6I="

class TestEncryptProtocol(unittest.TestCase):
    """Tests for the encryption protocol"""

    def test_output_count(self):
        """Tests that the encrypt method returns the correct number of strings"""
        protocol = EncryptionProtocol(padded_length = 10, desired_output_count = 7)

        encrypted = protocol.encrypt("asdf")

        self.assertEqual(len(encrypted), 7)
        with self.assertRaises(PreconditionError):
            EncryptionProtocol(padded_length = 10, desired_output_count = 1)

    def test_padding(self):
        """Tests that the encrypted strings are padded to the correct length"""
        protocol = EncryptionProtocol(padded_length = 10, desired_output_count = 2)

        encrypted_ascii = protocol.encrypt("123")
        encrypted_utf8 = protocol.encrypt("äbc")

        self.assertEqual(len(encrypted_ascii[0]), 10)
        self.assertEqual(len(encrypted_ascii[1]), 10)
        self.assertEqual(len(encrypted_utf8[0]), 10)
        self.assertEqual(len(encrypted_utf8[1]), 10)

    @patch('src.protocol.encrypt_bytes')
    def test_encrypt(self, mock_encrypt_bytes):
        """Tests that the encrypt bytes primitive is used correctly"""
        mock_encrypt_result=[[b'12345', b'98765'], [b'asdfe', b'zyxwv'], [b'hjklm', b'qwerty']]
        mock_encrypt_bytes.side_effect = copy.deepcopy(mock_encrypt_result)

        protocol = EncryptionProtocol(padded_length = 5, desired_output_count = 4)

        result = protocol.encrypt("abc")

        mock_encrypt_bytes.assert_has_calls([
            call(b'abc', 5),
            call(mock_encrypt_result[0][1], 5),
            call(mock_encrypt_result[1][1], 5)
        ])
        self.assertEqual(result, [
            mock_encrypt_result[0][0],
            mock_encrypt_result[1][0],
            *mock_encrypt_result[2]
        ])

    def test_encode_base32(self):
        """Tests that bytes are correctly encoded using base32"""
        protocol = EncryptionProtocol(padded_length = 5, desired_output_count = 4)
        input_byte_strings = [b"The quick brown fox", b"jumps over the lazy"]

        result = protocol.encode_base32(input_byte_strings)

        self.assertEqual(result, [THE_QUICK_BROWN_FOX_B32, JUMPS_OVER_THE_LAZY_DOG_B32])

class TestDecryptProtocol(unittest.TestCase):
    """Tests for the decryption protocol"""

    @patch('src.protocol.decrypt_bytes')
    def test_decrypt(self, mock_decrypt_bytes):
        """Tests that the decrypt bytes primitive is used correctly"""
        protocol = DecryptionProtocol()

        mock_encrypt_result = [b'zyxwv', b'98765', b'abc  ']
        mock_decrypt_bytes.side_effect = mock_encrypt_result

        protocol.decode_base32_and_store('KRUG KIDR')
        protocol.decode_base32_and_store('OVUW G2ZA')
        protocol.decode_base32_and_store('MJZG 653O')
        protocol.decode_base32_and_store('EBTG 66BA')
        result = protocol.decrypt(ignore_utf8_encoding_errors = False)

        mock_decrypt_bytes.assert_has_calls([
            call(b'The q', b'uick '),
            call(mock_encrypt_result[0], b'brown'),
            call(mock_encrypt_result[1], b' fox ')
        ])
        self.assertEqual(result, "abc  ")

    def test_decrypt_too_few_inputs(self):
        """Tests that an error is thrown if too few inputs are given"""
        protocol = DecryptionProtocol()
        protocol.decode_base32_and_store('KRUG KIDR')

        with self.assertRaises(PreconditionError):
            protocol.decrypt(ignore_utf8_encoding_errors = False)

    def test_decode_base32(self):
        """Tests that base32 strings are decoded correctly to bytes and
        decoding invalid base32 strings throws"""
        protocol = DecryptionProtocol()

        input1 = THE_QUICK_BROWN_FOX_B32
        input2 = JUMPS_OVER_THE_LAZY_DOG_B32
        input3 = "MRXW OLQ="

        protocol.decode_base32_and_store(input1)
        self.assertEqual(protocol.encrypted_bytes[0], b"The quick brown fox")

        protocol.decode_base32_and_store(input2)
        self.assertEqual(protocol.encrypted_bytes[1], b"jumps over the lazy")

        with self.assertRaises(ValidationError):
            protocol.decode_base32_and_store(input3)

    @patch('src.protocol.decrypt_bytes')
    def test_decrypt_encoding_failure(self, mock_decrypt_bytes):
        """Tests that when the decrypted bytes are invalid utf-8 an error is thrown
        or the invalid characters are replaced if the corresponding flag is set"""
        protocol = DecryptionProtocol()
        protocol.decode_base32_and_store("KRUG KIDR")
        protocol.decode_base32_and_store("NJ2W 24DT")

        mock_decrypt_bytes.return_value = b'ab\xFF  '

        with self.assertRaises(UnicodeDecodeError):
            protocol.decrypt(ignore_utf8_encoding_errors = False)

        result = protocol.decrypt(ignore_utf8_encoding_errors = True)
        self.assertEqual(result, "ab�  ")
