import pickle
import binascii
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import algorithms

# ../keyBag/unwrappedWPKY.pkl load
with open('../keyBag/CLAS1_UWPKY.pkl', 'rb') as f:
    WPKY = pickle.load(f)
    
# debug key len
# print("personal pw hash length:", len(personal_key))

# [input NS.data Key]
NSdataKey = binascii.unhexlify("57E8B65F911D254E28F672EB184EF66C5CCBF800DE5B32BDACA5ED474B583639C880CB0B686A9BB3")

# NSdataKeySliced = NSdataKey[4:]

# debug len chk
# print("NSdataKeySliced len:", len(NSdataKeySliced))

try:
    #unwrappedNSdataKey = aes_key_unwrap(WPKY, NSdataKeySliced, algorithms.AES)
    unwrappedNSdataKey = aes_key_unwrap(WPKY, NSdataKey, algorithms.AES)
    with open('../keyBag/keychainBackup.pkl', 'wb') as f:
        pickle.dump(unwrappedNSdataKey, f)
        print("file key saved at ../keyBag/keychainBackup.pkl")
except Exception as e:
    print("Error during unwrapping", str(e))
    print("file key:", binascii.hexlify(unwrappedNSdataKey).decode())