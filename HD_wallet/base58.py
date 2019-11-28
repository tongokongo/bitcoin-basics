import binascii
import hmac
import hashlib
import sys


def b58encode(v):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    print(binascii.hexlify(v))
    p, acc = 1, 0
    for c in reversed(v):
        print("\n")
        print("c: {}".format(c))
        acc += p * c
        print("acc: {}".format(acc))
        p = p << 8
        print("p: {}".format(p))

    string = ""
    while acc:
        print("\n\n")
        acc, idx = divmod(acc, 58)
        print(acc, idx)
        string = alphabet[idx : idx + 1] + string
    return string


test = binascii.unhexlify("4d616e")
print(b58encode(test))