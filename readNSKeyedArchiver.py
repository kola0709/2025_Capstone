from biplist import readPlist

try:
    plist_data = readPlist("./plist/keychain.plist")
    print(plist_data)
except Exception as e:
    print("plist parsing err", e)