import bip32utils
import binascii
import os


seed = binascii.unhexlify("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
bip32_root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
bip32_child_key_obj = bip32_root_key_obj.ChildKey(0)
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
        'bi32_root_key_public': binascii.hexlify(bip32_root_key_obj.PublicKey()).decode(),
        'bip32_extended_private_key': bip32_child_key_obj.ExtendedKey(),
        # 'path': "m/44'/0'/0'/0",
        'addr': bip32_child_key_obj.Address(),
        'publickey': binascii.hexlify(bip32_child_key_obj.PublicKey()).decode(),
        'privatekey': bip32_child_key_obj.WalletImportFormat(),
        'coin': 'BTC'
    }

print(dict)
