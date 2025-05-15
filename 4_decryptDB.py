import pickle
from Crypto.Cipher import AES
import os

with open('../keyBag/manifestKey.pkl', 'rb') as f:
    key = pickle.load(f)

iv = b"\x00" * 16

encryptedDBPath = "../encData/Manifest.db"
decryptedDBPath = "../decryptedData/decryptedManifest.db"

def decryptFile(encryptedDBPath, decryptedDBPath, key, iv):
    with open(encryptedDBPath, "rb") as encFile:
        encryptedData = encFile.read()
        
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decryptedData = cipher.decrypt(encryptedData)
    
    if len(decryptedData) % 16 != 0:
        decryptedData = decryptedData[:-(len(decryptedData) % 16)]
        
    with open(decryptedDBPath, "wb") as decFile:
        decFile.write(decryptedData)
        
    print(f"file decryption end: {decryptedDBPath}")

decryptFile(encryptedDBPath, decryptedDBPath, key, iv)