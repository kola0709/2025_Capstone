import plistlib

with open("../decryptedData/51_decrypted.plist") as f:
    try:
        plistData = plistlib.load(f)
        print(plistData)
    except Exception as e:
        print("plistlib로 읽기 실패")