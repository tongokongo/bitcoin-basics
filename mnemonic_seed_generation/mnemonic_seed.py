import os
import binascii
import hashlib
import unicodedata

bits = 256
print("Bytes = " + str(bits//8))
#r = os.urandom(bits//8)
random_bin = binascii.unhexlify("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c") #random in bin
random_hex = binascii.hexlify(random_bin) #random in hex
bytes = len(random_bin)

hashed_sha256 = hashlib.sha256(random_bin).hexdigest()
print("My sha256: " + str(hashed_sha256))

checksum = bits/32 #8 bits

bin_result = (
    bin(int(random_hex, 16))[2:].zfill(bytes * 8)
    + bin(int(hashed_sha256, 16))[2:].zfill(256)[: bytes * 8 // 32]
)
print("Bin result: " + str(bin_result))

index_list = []
with open("english.txt", "r", encoding="utf-8") as f:
    for w in f.readlines():
        index_list.append(w.strip())

wordlist = []
for i in range(len(bin_result) // 11):
    #print(bin_result[i*11 : (i+1)*11])
    index = int(bin_result[i*11 : (i+1)*11], 2)
    #print(str(index))
    wordlist.append(index_list[index])

phrase = " ".join(wordlist)
print(phrase)

#TO SEED
normalized_mnemonic = unicodedata.normalize("NFKD", phrase)
password = ""
normalized_passphrase = unicodedata.normalize("NFKD", password)

passphrase = "mnemonic" + normalized_passphrase
mnemonic = normalized_mnemonic.encode("utf-8")
passphrase = passphrase.encode("utf-8")

bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic, passphrase, 2048)
print(binascii.hexlify(bin_seed[:64]))