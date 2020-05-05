import binascii
import hmac
import hashlib
import ecdsa
import sys
from base58 import B58
from ecdsa.curves import SECP256k1


#seed = binascii.unhexlify("17e4b5661796eeff8904550f8572289317ece7c1cc1316469f8f4c986c1ffd7b9f4c3aeac3e1713ffc21fa33707d09d57a2ece358d72111ef7c7658e7b33f2d5") #seed in bin
seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
Il, Ir = I[:32], I[32:]
key = {
    "secret": Il, 
    "chain": Ir,
    "depth": 0,
    "index": 0, 
    "fpr": '\0\0\0\0'
}
k_priv = ecdsa.SigningKey.from_string(key["secret"], curve=SECP256k1)
K_priv = k_priv.get_verifying_key()
k_pub = None
K_pub = key["secret"]


Extended_priv = '0488ade4'.decode('hex') # Version string for mainnet extended private keys
Extended_pub  = '0488b21e'.decode('hex') # Version string for mainnet extended public keys
depth = chr(key["depth"])
fpr = key["fpr"]
child = struct.pack('>L', key["index"])  # >L -> big endian


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