import pickle
import binascii
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import algorithms

# ../keyBag/personalKey.pkl load
with open('../keyBag/CLAS3_UWPKY.pkl', 'rb') as f:
    unwrappedKey = pickle.load(f)
    
manifestKey = binascii.unhexlify("030000008257F858AF708A3BB6411860B4090A5B8B51A263AEA4EE662DDC80B9853A123A24438764A21DC2A7")
manifestKeySliced = manifestKey[4:]

try:
    unwrappedManifestKey = aes_key_unwrap(unwrappedKey, manifestKeySliced, algorithms.AES)
    with open('../keyBag/manifestKey.pkl', 'wb') as f:
        pickle.dump(unwrappedManifestKey, f)
        print("manifestkey saved at ../keyBag/manifestKey.pkl")
except Exception as e:
    print("Error druing unwrapping:", str(e))
    print("unwrapping key:", binascii.hexlify(unwrappedManifestKey).decode())