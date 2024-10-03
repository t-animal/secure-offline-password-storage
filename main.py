#!/usr/bin/env python3

"""Contains the main function of the application"""

import binascii
import argparse
import getpass
import sys

from src.exceptions import PreconditionError, ValidationError
from src.protocol import EncryptionProtocol, DecryptionProtocol

DEFAULT_PAD_LENGTH = 50

def main():
    """Parses the argument and calls the encrypt or decrypt flow"""
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a string using one-time-pad for secure storage"
    )

    subparsers = parser.add_subparsers(dest='command', help="Choose either 'encrypt' or 'decrypt'")

    encrypt_parser = subparsers.add_parser(
        'encrypt',
        help="Encrypt a string. The string will be read from stdin"
    )
    encrypt_parser.add_argument(
        'output_count',
        type=int,
        help="The number of output strings to generate. Must be at least 2"
    )

    subparsers.add_parser('decrypt', help="Decrypt a list of strings")

    args = parser.parse_args()

    # Execute the appropriate function based on the command
    if args.command == 'encrypt':
        encrypt_flow(args.output_count)
    elif args.command == 'decrypt':
        decrypt_flow()
    else:
        parser.print_help()

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


def decrypt_flow():
    """Guides the user through decryption"""
    print("Please enter the encrypted strings line by line. Confirm with an empty line.")

    protocol = DecryptionProtocol()
    while True:
        try:
            next_string = input("Next encrypted string: ")
            if next_string == "":
                break

            protocol.decode_base32_and_store(next_string)
        except EOFError:
            print("Received EOF. Exiting.")
            sys.exit(0)
        except binascii.Error:
            print(
                "This input doesn't have a valid base32 encoding. You probably have a spelling "
                "error somewhere. The current line is ignored"
            )
            continue
        except ValidationError:
            print(
                "All inputs must have same length. The current line's length differs from the "
                "previous lines'. The current line is ignored."
            )
            continue

    print('---')
    try :
        decoded = protocol.decrypt(False)
        print(f"Your original was: {decoded}")
    except PreconditionError:
        print("Must enter at least two strings")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(f"An error occured while decoding your input: {e}")
        print("Double-check that you've entered the correct strings.")
        print('---')
        retry = input(
            "You can try ignoring this and all other potential errors, but it will not give you "
            "your exact original input. But maybe it's close enough so that you remember it. "
            "Try ignoring errors? (Y/n)"
        )
        if not retry.lower() == "n":
            try:
                decoded = protocol.decrypt(True)
                print(f"Your original was probably close to: {decoded}")
            except: # Catching all exceptions on purpose pylint: disable=W0702
                print(
                    "The string could still not be decoded. Double check that you have all "
                    "inputs and that they are correct."
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
