"""Contains the encrypt flow guiding the user through encryption"""

import getpass
import sys

from src.protocol import EncryptionProtocol

DEFAULT_PAD_LENGTH = 50

def encrypt_flow(output_count: int):
    """Guides the user through encryption"""
    if output_count < 2:
        print("Output count must be at least 2")
        sys.exit(1)

    print(f"Will create {output_count} output strings for you to write down")

    secret = getpass.getpass("Please enter the secret string:")

    if secret == "":
        sys.exit(0)

    try:
        pad_input = input(
            "To increase security, you can add whitespace to the input to "
            "obfuscate the length of the secret string. What length should the output "
            f"have? Defaults to {DEFAULT_PAD_LENGTH} (your input has "
            f"{len(secret.encode("utf-8"))} bytes)"
        )
        if pad_input == "":
            padded_length = DEFAULT_PAD_LENGTH
        else:
            padded_length = int(pad_input)
            print(f"Will pad the output length to {padded_length} bytes")
    except ValueError:
        print("Could not read your input as a number")
        sys.exit(1)

    try:
        protocol = EncryptionProtocol(padded_length, output_count)
        encrypted = protocol.encrypt(secret)
        encoded = protocol.encode_base32(encrypted)
    except: # Catching all exceptions on purpose pylint: disable=W0702
        print("Encryption failed")
        sys.exit(1)

    print(
        "Write this to paper. " 
        "It is a good idea to run a test-decryption after that to ensure no misspellings"
    )
    for string in encoded:
        print("")
        print(string)
