import binascii


class B58()

    def b58encode(self, v):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        print(binascii.hexlify(v))
        p, acc = 1, 0
        for c in reversed(v):
            print("c: {}".format(c))
            acc += p * c
            print("acc: {}".format(acc))
            p = p << 8
            print("p: {}".format(p))

        string = ""
        while acc:
            acc, idx = divmod(acc, 58)
            string = alphabet[idx : idx + 1] + string
        return string
