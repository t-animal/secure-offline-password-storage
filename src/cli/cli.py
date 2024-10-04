"""Contains the argument parsing function"""

import argparse

from src.cli.decrypt_flow import decrypt_flow
from src.cli.encrypt_flow import encrypt_flow

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
