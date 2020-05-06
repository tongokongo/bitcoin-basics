import binascii
import hmac
import hashlib
import ecdsa
import sys
import struct
from base58 import B58
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string


#seed = binascii.unhexlify("17e4b5661796eeff8904550f8572289317ece7c1cc1316469f8f4c986c1ffd7b9f4c3aeac3e1713ffc21fa33707d09d57a2ece358d72111ef7c7658e7b33f2d5") #seed in bin
seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
Il, Ir = I[:32], I[32:]  # Divide 
key = {
    "secret": Il, 
    "chain": Ir,
    "depth": b"\x00",
    "index": 0, 
    "fpr": b'\0\0\0\0'
}
k_priv = ecdsa.SigningKey.from_string(key["secret"], curve=SECP256k1)
K_priv = k_priv.get_verifying_key()
public = False

Extended_priv = binascii.unhexlify("0488ade4") # Version string for mainnet extended private keys
Extended_pub  = binascii.unhexlify("0488b21e") # Version string for mainnet extended public keys

depth = key["depth"]
fpr = key["fpr"]
child = struct.pack('>L', key["index"])  # >L -> big endian -> the way of storing values starting from most significant value in sequence
chain = key["chain"]

data_priv = b'\x00' + (k_priv.to_string())
data_pub = None
if K_priv.pubkey.point.y() & 1:
    data_pub= b'\3'+int_to_string(K_priv.pubkey.point.x())
else:
    data_pub = b'\2'+int_to_string(K_priv.pubkey.point.x())

# print("Type \nExtended_priv: {} \ndepth: {} \nfpr: {} \nchild: {} \nchain: {} \ndata: {}"
# .format(type(Extended_priv), type(depth), type(fpr), type(child), type(chain), type(data_priv)))
raw_priv = Extended_priv + depth + fpr + child + chain + data_priv
raw_pub = Extended_pub + depth + fpr + child + chain + data_pub

# Double hash using SHA256
hashed_xprv = hashlib.sha256(raw_priv).digest()
hashed_xprv = hashlib.sha256(hashed_xprv).digest()
hashed_xpub = hashlib.sha256(raw_pub).digest()
hashed_xpub = hashlib.sha256(hashed_xpub).digest()

# Append 4 bytes of checksum
raw_priv += hashed_xprv[:4]
raw_pub += hashed_xpub[:4]


# Return base58
print(B58.b58encode(raw_priv))
print(B58.b58encode(raw_pub))

'''
seed = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest() #compute HMAC-SHA512 of seed Key= "Bitcoin seed" Data = seed

# Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
#xpub = binascii.unhexlify("0488b21e")  # Version for public_key mainnet
xprv = binascii.unhexlify("0488ade4")  # Version for private_key mainnet
xprv += b"\x00"   # Depth 0x00 for master nodes, 0x01 for level-1 derived keys
xprv += binascii.unhexlify("00000000") # Parent's key fingerprint
xprv += binascii.unhexlify("00000000") # Child number
xprv += seed[32:]  # Chain code
xprv += b"\x00" + seed[:32]  # Master key

print("Length xpr: " + str(len(xprv))) #should be 78 byte

# Double hash using SHA256
hashed_xprv = hashlib.sha256(xprv).digest()
hashed_xprv = hashlib.sha256(hashed_xprv).digest()

# Append 4 bytes of checksum
xprv += hashed_xprv[:4]


# Return base58
print(B58.b58encode(xprv))
'''