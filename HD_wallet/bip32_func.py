import binascii
import hmac
import hashlib
import ecdsa
import sys
import struct
from base58 import B58

from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int

CURVE_GEN       = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER     = CURVE_GEN.order()
BIP32_HARDEN    = 0x80000000 # choose from hardened set of child keys

def bip32_key(secret, chain, depth, index, fpr):
    # Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
    xprv = binascii.unhexlify("0488ade4") # Version string for mainnet extended private keys
    xpub = binascii.unhexlify("0488b21e") # Version string for mainnet extended public keys
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
    return [data_pub, chain, k_priv, K_priv]

#seed = binascii.unhexlify("17e4b5661796eeff8904550f8572289317ece7c1cc1316469f8f4c986c1ffd7b9f4c3aeac3e1713ffc21fa33707d09d57a2ece358d72111ef7c7658e7b33f2d5") #seed in bin
seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")

#chain m
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest() #compute HMAC-SHA512 of seed Key= "Bitcoin seed" Data = seed
Il, Ir = I[:32], I[32:]  # Divide HMAC into "Left" and "Right" section of 32 bytes each :) 
data_pub, chain, k_priv, K_priv = bip32_key(Il, Ir, b'\x00', 0, b'\0\0\0\0')

# chain m/0
ITERATE = 0  + BIP32_HARDEN  # because chain m/0
i_str = struct.pack(">L", ITERATE)

# for non-hardened derivation
# data = data_pub + i_str 

# for hardened derivation                      
data = b'\0' + k_priv.to_string() + i_str

I = hmac.new(chain, data, hashlib.sha512).digest()
Il, Ir = I[:32], I[32:]

Il_int = string_to_int(Il)
pvt_int = string_to_int(k_priv.to_string())
k_int = (Il_int + pvt_int) % CURVE_ORDER
secret = (b'\0'*32 + int_to_string(k_int))[-32:]
depth = bytes([1])

#fingrprint:
padx = (b'\0'*32 + int_to_string(K_priv.pubkey.point.x()))[-32:]
if K_priv.pubkey.point.y() & 1:
    ck = b'\3'+padx
else:
    ck = b'\2'+padx
fingerprint = hashlib.new('ripemd160', sha256(ck).digest()).digest()[:4]

new_data_pub, new_chain, new_k_priv, new_K_priv = bip32_key(secret, Ir, depth, ITERATE, fingerprint)