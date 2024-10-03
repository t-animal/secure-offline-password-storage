import binascii
import argparse
import getpass
import math
import sys

from lib.exceptions import PreconditionError, ValidationError
from lib.protocol import EncryptionProtocol, DecryptionProtocol

DEFAULT_PAD_LENGTH = 50

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a string using one-time-pad for secure storage")
    
    subparsers = parser.add_subparsers(dest='command', help="Choose either 'encrypt' or 'decrypt'")

    encrypt_parser = subparsers.add_parser('encrypt', help="Encrypt a string. The string will be read from stdin")
    encrypt_parser.add_argument('outputCount', type=int, help="The outputCount of output strings to generate. Must be at least 2")
    
    decrypt_parser = subparsers.add_parser('decrypt', help="Decrypt a list of strings")

    args = parser.parse_args()

    # Execute the appropriate function based on the command
    if args.command == 'encrypt':
        encryptFlow(args.outputCount)
    elif args.command == 'decrypt':
        result = decryptFlow()
    else:
        parser.print_help()

def encryptFlow(outputCount: int):
    if outputCount < 2:
        print("Output count must be at least 2")
        sys.exit(1)

    print("Will create {} output strings for you to write down".format(outputCount))

    secret = getpass.getpass("Please enter the secret string:")

    if secret == "":
        sys.exit(0)

    try:
        padInput = input("To increase security, you can add whitespace to the input to obfuscate the length of the secret string. What length should the output have? Defaults to {} (your input has {} bytes)".format(DEFAULT_PAD_LENGTH, len(secret.encode("utf-8"))))
        if padInput == "":
            paddedLength = DEFAULT_PAD_LENGTH
        else:
            paddedLength = int(padInput)
            print("Will pad the output length to {} bytes".format(paddedLength))
    except ValueError as e:
        print("Could not read your input as a number")
        sys.exit(1)

    try: 
        protocol = EncryptionProtocol(paddedLength, outputCount)
        encrypted = protocol.encrypt(secret)
        encoded = protocol.encodeBase32(encrypted)
    except e:
        print("Encryption failed")
        sys.exit(1)

    print("Write this to paper. It is a good idea to run a test-decryption after that to ensure no misspellings")
    for string in encoded: 
        print("")
        print(string)


def decryptFlow():
    print("Please enter the encrypted strings line by line. Confirm with an empty line.")

    protocol = DecryptionProtocol()
    while True:
        try:
            nextString = input("Next encrypted string: ")
            if nextString == "":
                break

            protocol.decodeBase32AndStore(nextString)
        except EOFError:
            print("Received EOF. Exiting.")
            sys.exit(0)
        except binascii.Error:
            print("This input doesn't have a valid base32 encoding. You probably have a spelling error somewhere. The current line is ignored")
            continue
        except ValidationError:
            print("All inputs must have same length. The current line's length differs from the previous lines'. The current line is ignored.")
            continue

    print('---')
    try :
        decoded = protocol.decrypt(False)
        print("Your original was: " + decoded)
    except PreconditionError:
        print("Must enter at least two strings")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print("An error occured while decoding your input: {}".format(e))
        print("Double-check that you've entered the correct strings.")
        print('---')
        retry = input("You can try ignoring this and all other potential errors, but it will not give you your exact original input. But maybe it's close enough so that you remember it. Try ignoring errors? (Y/n)")
        if not retry.lower() == "n":
            try:
                decoded = protocol.decrypt(True)
                print("Your original was probably close to: " + decoded)
            except UnicodeDecodeError as e:
                print("The string could still not be decoded. Double check that you have all inputs and that they are correct.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass