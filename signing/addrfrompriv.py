import ecdsa
import hashlib
import base58

# answer to https://bitcoin.stackexchange.com/questions/96190
# WIF to private key by https://en.bitcoin.it/wiki/Wallet_import_format
Private_key = base58.b58decode_check("5JYJWrRd7sbqEzL9KR9dYTGrxyLqZEhPtnCtcvhC5t8ZvWgS9iC") 
Private_key = Private_key[1:]

# Private key to public key (ecdsa transformation)
signing_key = ecdsa.SigningKey.from_string(Private_key, curve = ecdsa.SECP256k1)
verifying_key = signing_key.get_verifying_key()
public_key = bytes.fromhex("04") + verifying_key.to_string()

# hash sha 256 of pubkey
sha256_1 = hashlib.sha256(public_key)

# hash ripemd of sha of pubkey
ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha256_1.digest())

# checksum
hashed_public_key = bytes.fromhex("00") + ripemd160.digest()
checksum_full = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()
checksum = checksum_full[:4]
bin_addr = hashed_public_key + checksum

# encode address to base58 and print
result_address = base58.b58encode(bin_addr)
print ("Bitcoin address {}".format(result_address))