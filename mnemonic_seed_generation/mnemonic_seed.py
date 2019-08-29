import os
import binascii
import hashlib

bits = 256
bytes = int(bits/8) #32 bytes
random_256 = binascii.hexlify(os.urandom(bytes))
bin_random_256 = binascii.unhexlify(random_256)


print("My random hex " + str(bits) + "  bits number: " + random_256.decode("utf-8"))
#how to print bin_random_256

hashed_sha_256 = hashlib.sha256(random_256).hexdigest()
print(hashed_sha_256)

entropy = bits/32 #8 bits = 2hex characters


my_hexdata = "ff"
num_of_bits = 8
print(bin(int(my_hexdata, 16))[2:].zfill(num_of_bits)) #16 = hexadecimal base



b = (
        bin(int(random_256, 16))[2:].zfill(bytes * 8)
        + bin(int(hashed_sha_256, 16))[2:].zfill(256)[: bytes * 8 // 32]
)

index_list = []
with open("english.txt", "r", encoding="utf-8") as f:
    for w in f.readlines():
        index_list.append(w.strip())


wordlist = []
print(str(len(b) / 11))
for i in range(len(b) // 11):
    print(b[i*11 : (i + 1)*11])
    index = int(b[i * 11 : (i + 1) * 11], 2)
    print(str(index))
    wordlist.append(index_list[index])

print(wordlist)






