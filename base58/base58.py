import binascii

def b58encode(v):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    print(binascii.hexlify(v))
    lev, number = 1, 0
    for char in reversed(v):
        print("\nchar: {}".format(char))
        number += lev * char
        print("number: {}".format(number))
        lev = lev << 8
        print("lev: {}".format(lev))

    string = ""
    while number:
        print("\n\n")
        number, modulo = divmod(number, 58)
        print("\n\n number: {} modulo: {} ".format(number, modulo))
        string = alphabet[modulo : modulo + 1] + string
    return string


test = binascii.unhexlify("4d61")
print(b58encode(test))