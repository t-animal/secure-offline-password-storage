#!/usr/bin/env python3

""" Uppermost entry point to the application. The CLI resides in src/cli and the implementation
in src/protocol.py and src/primitives.py"""

if __name__ == "__main__":
    from src.cli.cli import main

    try:
        main()
    except KeyboardInterrupt:
        pass
