# import ecdsa
# import hashlib
# import binascii


# message = binascii.hexlify(b'''Craig Steven Wright is a liar and a fraud. He doesn't have the keys used to sign this message.

# The Lightning Network is a significant achievement. However, we need to continue work on improving on-chain capacity.

# Unfortunately, the solution is not to just change a constant in the code or to allow powerful participants to force out others.

# We are all Satoshi''')

# public_key = '04e5d980b2ec08c9e24f354e70bde2d60c8d7c33041bc88f0ac11555feae642554050f14e640a78c115f3b67022c374a910dce06caedd09e9496a0f6cff26f1fbf'
# sig = binascii.hexlify(b'G3SsgKMKAOiOaMzKSGqpKo5MFpt0biP9MbO5UkSl7VxRKcv6Uz+3mHsuEJn58lZlRksvazOKAtuMUMolg/hE9WI=')
# print(type(message))
# vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256) # the default is sha1
# a = vk.verify(sig, message) # True

import ecdsa
import base64
import hashlib

class DoubleSha256:

    def __init__(self, *args, **kwargs):
        self._m = hashlib.sha256(*args, **kwargs)

    def __getattr__(self, attr):
        if attr == 'digest':
            return self.double_digest
        return getattr(self._m, attr)

    def double_digest(self):
        m = hashlib.sha256()
        m.update(self._m.digest())
        return m.digest()


def pad_message(message):
    return "\x18Bitcoin Signed Message:\n".encode('UTF-8') + bytes([len(message)]) + message.encode('UTF-8')


public_key_hex = '04e5d980b2ec08c9e24f354e70bde2d60c8d7c33041bc88f0ac11555feae642554050f14e640a78c115f3b67022c374a910dce06caedd09e9496a0f6cff26f1fbf'
public_key = bytes.fromhex(public_key_hex)
message = pad_message('''Craig Steven Wright is a liar and a fraud. He doesn't have the keys used to sign this message.

The Lightning Network is a significant achievement. However, we need to continue work on improving on-chain capacity.

Unfortunately, the solution is not to just change a constant in the code or to allow powerful participants to force out others.

We are all Satoshi''')
sig = base64.b64decode('G3SsgKMKAOiOaMzKSGqpKo5MFpt0biP9MbO5UkSl7VxRKcv6Uz+3mHsuEJn58lZlRksvazOKAtuMUMolg/hE9WI=')

# public_key_hex = '026b4cc594c849a0d9a124725997604bc6a0ec8f100b621b1eaed4c6094619fc46'
# public_key = bytes.fromhex(public_key_hex)
# message = pad_message('aaa')
# sig = base64.b64decode('IHQ7FDJy6zjwMImIsFcHGdhVxAH7ozoEoelN2EfgKZZ0JVAbvnGN/w8zxiMivqkO8ijw8fXeCMDt0K2OW7q2GF0=')

vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
print(vk.verify(sig[1:], message, hashfunc=DoubleSha256))


# https://github.com/bitcoin/bitcoin/blob/9af3c3c8249785a0106c14bce1cb72b3afc536e8/src/bitcoinrpc.cpp#L661
# https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
# https://github.com/nanotube/supybot-bitcoin-marketmonitor
# https://bitcoin.stackexchange.com/questions/62446/signature-verification-in-python
# https://bitcoin.stackexchange.com/questions/72657/signature-verification-in-python-using-compressed-public-key