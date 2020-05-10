import bip32utils
import binascii
import os


seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
bip32_root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
bip32_child_key_obj = bip32_root_key_obj.ChildKey(0 + bip32utils.BIP32_HARDEN)
    # return {
    #     'mnemonic_words': mnemonic_words,
    #     'bip32_root_key': bip32_root_key_obj.ExtendedKey(),
    #     'bip32_extended_private_key': bip32_child_key_obj.ExtendedKey(),
    #     'bip32_derivation_path': "m/44'/0'/0'/0",
    #     'bip32_derivation_addr': bip32_child_key_obj.Address(),
    #     'coin': 'BTC'
    # }

dict =  {
        'bip32_root_key': bip32_root_key_obj.ExtendedKey(),  # private=False
        # 'bi32_root_key_public': binascii.hexlify(bip32_root_key_obj.PublicKey()).decode(),
        'bip32_extended_private_key': bip32_child_key_obj.ExtendedKey(),
        # 'path': "m/44'/0'/0'/0",
        # 'addr': bip32_child_key_obj.Address(),
        # 'publickey': binascii.hexlify(bip32_child_key_obj.PublicKey()).decode(),
        # 'privatekey': bip32_child_key_obj.WalletImportFormat(),
        # 'coin': 'BTC'
    }

for k in dict:
    print(k, dict[k])
