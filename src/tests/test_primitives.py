"""Tests for primitives.py"""
import unittest
from unittest.mock import patch

from src.exceptions import PreconditionError
from src.primitives import decrypt_bytes, encrypt_bytes, xor_tuple

class TestEncryptDecryptPrimitives(unittest.TestCase):
    """Unit tests for encrypting and decrypting"""
    def test_xor_tuple(self):
        """Tests XORin tuples"""
        xored_0_from_0_0 = xor_tuple((0,0))
        xored_0_from_1_1 = xor_tuple((1,1))
        xored_3_from_1_2 = xor_tuple((1,2))
        xored_3_from_2_1 = xor_tuple((2,1))

        self.assertEqual(xored_0_from_0_0, 0)
        self.assertEqual(xored_0_from_1_1, 0)
        self.assertEqual(xored_3_from_1_2, 3)
        self.assertEqual(xored_3_from_2_1, 3)

    @patch('secrets.token_bytes')
    def test_encrypt_mocked_secret(self, mock_token_bytes):
        """Tests encrypting a value and mocks the random secret generator for reproducability"""
        mock_token_bytes.return_value = b'abcde'

        encrypted = encrypt_bytes(b"abcde", 5)
        self.assertEqual(encrypted, (b'abcde', bytes([0]*5)))

        encrypted = encrypt_bytes(b"bcdef", 5)
        self.assertEqual(encrypted,
            (b'abcde', bytes([
                ord('a')^ord('b'),
                ord('b')^ord('c'),
                ord('c')^ord('d'),
                ord('d')^ord('e'),
                ord('e')^ord('f')
            ]))
        )

        encrypted = encrypt_bytes(b"abc", 5)
        self.assertEqual(encrypted,
            (b'abcde', bytes([0]*3 + [ord('D'), ord('E')]))
        ) # xor with ' ' shifts case

    def test_encrypt(self):
        """Tests encrypting against another implementation"""
        test_input = b"123"

        encrypted = encrypt_bytes(test_input, 3)

        self.assertEqual(bytes(map(xor_tuple, zip(*encrypted))), test_input)

    def test_padding(self):
        """Tests padding of the input string before encrypting"""
        test_input = b"123"

        encrypted = encrypt_bytes(test_input, 10)

        self.assertEqual(bytes(map(xor_tuple, zip(*encrypted))), test_input + b" " * 7)

    def test_too_short_padding(self):
        """Tests error handling in case the string cannot be padded"""
        encrypt_bytes(b"12345", 5)

        with self.assertRaises(PreconditionError):
            encrypt_bytes(b"123456", 5)

        with self.assertRaises(PreconditionError):
            # ä is encoded as two bytes
            encrypt_bytes("1234ä".encode("utf-8"), 5)

    def test_encrypt_decrypt(self):
        """Tests encrypting and then decrypting a string"""
        test_input = b"123"

        decrypted = decrypt_bytes(*encrypt_bytes(test_input, 3))

        self.assertEqual(decrypted, test_input)

    def test_decrypt_inequal_length(self):
        """Tests decrypting with two strings that don't have the same length"""
        with self.assertRaises(PreconditionError):
            decrypt_bytes(b'123', b'12')
