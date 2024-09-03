# Secure Offline Password Storage

If you have ever sat before your keyboard, not remembering your password and panicking, this project
is for you.

This tool encrypts a password using a one-time-pad multiple times. It then returns all the secrets
and the encrypted value in base32 encoded strings. These strings can be copied manually (or printed,
but beware of potential security flaws, see below) to a piece of paper. Each string can be stored 
in a different location. Only all strings together, when re-entered into the application, can be
combined to the original input. If any paper is lost or destroyed, the secret has been wiped. This
makes it useful for storing passwords securely offline.

## Example usage
```
> python main.py --help
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
> python main.py encrypt 3 
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
> python main.py decrypt
Please enter the encrypted strings line by line. Confirm with an empty line.
Next encrypted string: 5MWZ NQQP O6I3 WN6J
Next encrypted string: PKAB BNKO JFIY G2E3
Next encrypted string: 4LEO KBJE JLQB Q73S
Next encrypted string: 
Your original was: 
secret
```

## A note on printing and paper

While you could print the strings on a piece of paper, with printers these days the printed document
could pass several machines not under your control or the printer might even ahve some internal 
storage or whatnot. In any case, it's wise not to print the generated strings. Additional caution
should be taken when choosing the paper and pen.
For more info consult the excellent information at
https://github.com/cyphar/paperback?tab=readme-ov-file#paper-choices-and-storage


## Related projects and the why?!

Related projects often use shamir secret share. The most notable project certainly is
[paperback](https://github.com/cyphar/paperback). If it were in a completed state I would consider 
using it. However, its algorithm and innner workings are not as easily understandable as with this
project. If all goes wrong, you could still recover all the paper slips and undo the encryption by
hand. It's also so little code it can be easily reviewed by anyone familiar with python (and I
welcome feedback). Of course, this project has the huge drawback of much more manual effort for 
writing down and confirming the written down paper slips. However, since this is a disaster-recovery
mechanism, it's likely you don't have to do it often (or, if you do, you likely have other problems)
and distributing and recovering the paper slips is the bigger effort to writing down the secret
strings.

## Known problems

1. This ships its own one-time-pad implementation and even though this is a very simple algorithm, 
   mistakes can always happen. I'm very open to feedback.
2. The implementation does not protect against side-channel-attacks like timing attacks during 
   encryption or decryption, apart from the padding of the input, which also serves as obfuscation
   of how long the original string is.
3. Writing down the secret strings is tedious and error-prone. It is recommended to decrypt *from
   paper* after copying. Also, make sure that you don't leave imprints on other pieces of paper 
   lying below the one you're writing to.
