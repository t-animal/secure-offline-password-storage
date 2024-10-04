"""Contains the decrypt flow guiding the user through decryption"""

import binascii
import sys

from src.exceptions import PreconditionError, ValidationError
from src.protocol import DecryptionProtocol


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
