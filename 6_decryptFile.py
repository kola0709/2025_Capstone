import pickle
import os
from Crypto.Cipher import AES

# ../keyBag/fileKey.pkl load
with open('../keyBag/keychainBackup.pkl', 'rb') as f:
    fileKey = pickle.load(f)
    
# debug key len
# print("fileKey length:", len(fileKey))

iv = b"\x00" * 16

encryptedFilePath = "../encData/keychainEncrypt"
decryptedFilePath = "../decryptedData/keychainDecrypt.db"

def decrypt_file(encryptedFilePath, decryptedFilePath, fileKey, iv):
    with open(encryptedFilePath, "rb") as encFile:
        encryptedData = encFile.read()
        
    cipher = AES.new(fileKey, AES.MODE_CBC, iv)
    
    decryptedData = cipher.decrypt(encryptedData)
    
    if len(decryptedData) % 16 != 0:
        decryptedData = decryptedData[:-(len(decryptedData) % 16)]
        
    with open(decryptedFilePath, "wb") as decFile:
        decFile.write(decryptedData)
        
    print(f"file decryption end: {decryptedFilePath}")
    
decrypt_file(encryptedFilePath, decryptedFilePath, fileKey, iv)