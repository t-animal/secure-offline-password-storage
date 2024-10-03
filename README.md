# Secure Offline Password Storage
If you've ever found yourself sitting at your keyboard, unable to 
remember a password and feeling panicked, this project is for you.

This tool encrypts a password using a one-time-pad multiple times. It
then outputs the encryption in the form of base32-encoded strings,
along with the secrets used. These strings can be manually copied (or
printed, but see
[the security warning below](#Notes-on-Printing-and-Paper)) and stored
on paper. Each string can be stored in a separate location. The
original input can only be recovered if all the strings are re-entered
into the application. If any of the papers are lost or destroyed, the
secret is permanently wiped. This makes the tool ideal for securely
storing passwords offline.

## Example usage
```
> ./main.py --help
usage: main.py [-h] {encrypt,decrypt} ...

Encrypt or decrypt a string using one-time-pad for secure storage

positional arguments:
  {encrypt,decrypt}  Choose either 'encrypt' or 'decrypt'
    encrypt          Encrypt a string. The string will be read from stdin
    decrypt          Decrypt a list of strings

options:
  -h, --help         show this help message and exit
```

```
> ./main.py encrypt 3 
Will create 3 output strings for you to write down
Please enter the secret string:
To increase security, you can add whitespace to the input to obfuscate the length of the secret string. What length should the output have? Defaults to 50 (your input has 6 bytes)10
Will pad the output length to 10 bytes
Write this to paper. It is a good idea to run a test-decryption after that to ensure no misspellings

5MWZ NQQP O6I3 WN6J

PKAB BNKO JFIY G2E3

4LEO KBJE JLQB Q73S
```

```
> ./main.py decrypt
Please enter the encrypted strings line by line. Confirm with an empty line.
Next encrypted string: 5MWZ NQQP O6I3 WN6J
Next encrypted string: PKAB BNKO JFIY G2E3
Next encrypted string: 4LEO KBJE JLQB Q73S
Next encrypted string: 
Your original was: 
secret
```

## Notes on Printing and Paper

While you could print the strings on paper, modern printers may pass
the printed document through various systems outside your control.
Some printers even have internal storage. As a result, it's generally
more secure not to print the generated strings and resort to writing
by hand. Consider taking extra precautions when selecting paper and
pen for writing down your secrets. For more information, see the
excellent guide at:
https://github.com/cyphar/paperback?tab=readme-ov-file#paper-choices-and-storage


## Related Projects and Motivation
Many related projects use Shamir's Secret Sharing. The most notable is
[paperback](https://github.com/cyphar/paperback). While paperback is
excellent, it is not quite finished yet. Another problem is that its
algorithm and internal workings are less transparent compared to this
project. If you ever lost this implementation, you could still
manually recover the paper slips and undo the encryption by hand.

This project is small and easily reviewable for anyone familiar with
Python (feedback is welcome). It does require more manual effort to
write down and verify the paper slips, but since it's designed for
disaster recovery, you hopefully won’t need to do this often. If
frequent, you might have other underlying issues. Distributing and
recovering the paper slips will likely be a bigger challenge than
writing down the secret strings.

## Known Issues

1. This project includes its own one-time pad implementation.
   Although it's a simple algorithm, mistakes can always happen.
   I'm open to feedback.
2. The implementation doesn't protect against side-channel attacks
   like timing attacks during encryption or decryption, except for
   padding the input to obscure the original string's length.
3. Writing down the secret strings can be tedious and prone to error.
   It’s recommended to test the decryption process *from the written
   paper* to ensure accuracy. Also, ensure you don’t leave imprints
   on paper sheets underneath the one you're writing on.

## Dependencies
No dependencies are needed for running the code, except python >3.9.
For development, mypy and pylint are needed.