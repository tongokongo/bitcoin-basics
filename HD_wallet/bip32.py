import binascii
import hmac
import hashlib
import ecdsa
import struct
from base58 import B58
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int


#chain m
#seed = binascii.unhexlify("17e4b5661796eeff8904550f8572289317ece7c1cc1316469f8f4c986c1ffd7b9f4c3aeac3e1713ffc21fa33707d09d57a2ece358d72111ef7c7658e7b33f2d5") #seed in bin
seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")  # generate a seed byte sequence S of a chosen length (beween 128 and 512 bits)
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest() #calculate HMAC-SHA512 of seed Key= "Bitcoin seed" Data = seed
Il, Ir = I[:32], I[32:]  # Divide HMAC into "Left" and "Right" section of 32 bytes each :) 

# Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
secret = Il # left section of HMAC: source to generate keypair
chain = Ir # right section of HMAC: chain code
xprv = binascii.unhexlify("0488ade4") # Version string for mainnet extended private keys
xpub = binascii.unhexlify("0488b21e") # Version string for mainnet extended public keys
depth = b"\x00" # Child depth; parent increments its own by one when assigning this
fpr = b'\0\0\0\0' # Parent fingerprint,
index = 0  # Child index
child = struct.pack('>L', index)  # >L -> big endian -> the way of storing values starting from most significant value in sequence

k_priv = ecdsa.SigningKey.from_string(secret, curve=SECP256k1)
K_priv = k_priv.get_verifying_key()

data_priv = b'\x00' + (k_priv.to_string())
if K_priv.pubkey.point.y() & 1:
    data_pub= b'\3'+int_to_string(K_priv.pubkey.point.x())
else:
    data_pub = b'\2'+int_to_string(K_priv.pubkey.point.x())

raw_priv = xprv + depth + fpr + child + chain + data_priv
raw_pub = xpub + depth + fpr + child + chain + data_pub

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