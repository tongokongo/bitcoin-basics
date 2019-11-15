import binascii
import hmac
import hashlib
import sys

iseq, bseq, buffer = (
        lambda s: s,
        bytes,
        lambda s: s.buffer,
    )


BITCOIN_ALPHABET = \
    b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def scrub_input(v):
    if isinstance(v, str) and not isinstance(v, bytes):
        v = v.encode('ascii')

    return v

def b58encode_int(i, default_one=True, alphabet=BITCOIN_ALPHABET):
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    string = b""
    while i:
        i, idx = divmod(i, 58)
        string = alphabet[idx:idx+1] + string
    return string

def b58encode(v, alphabet=BITCOIN_ALPHABET):
    """
    Encode a string using Base58
    """
    v = scrub_input(v)

    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in iseq(reversed(v)):
        acc += p * c
        p = p << 8
    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return alphabet[0:1] * nPad + result


#seed = binascii.unhexlify("17e4b5661796eeff8904550f8572289317ece7c1cc1316469f8f4c986c1ffd7b9f4c3aeac3e1713ffc21fa33707d09d57a2ece358d72111ef7c7658e7b33f2d5") #seed in bin
seed = binascii.unhexlify("61")
print(seed)
print(b58encode(seed))