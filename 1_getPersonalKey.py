import hashlib
import hmac
import binascii
import pickle

def pbkdf2(hashName, password, salt, iteration, dklen):
    return hashlib.pbkdf2_hmac(hashName, password, salt, iteration, dklen)

password = b"rlaeoghks200*"

# PBKDF2-HMAC-SHA256: 1st hashing personal input key salt
DPSL = binascii.unhexlify("7CD3C5B69E6B7AB5A49F4EF52D03924097E308A6")

# PBKDF2-HMAC-SHA256: 1st hashing personal input key iteration
DPIC = 10000000

# PBKDF2-HMAC-SHA1: 2nd hashing after PBKDF2-HMAC-SHA256 salt
SALT = binascii.unhexlify("4D539D42D467BCE3EE67F069BA756D66648781C8")

# PBKDF2-HMAC-SHA1: 2nd hashing after PBKDF2-HMAC-SHA256 iteration
ITER = 10000

# derivated key = PBKDF2-HMAC-SHA256
intermediateKey = pbkdf2('sha256', password, DPSL, DPIC, 32)

# real hashed personal key
personalKey = pbkdf2('sha1', intermediateKey, SALT, ITER, 32)

try:
    with open('../keyBag/personalKey.pkl', 'wb') as f:
        pickle.dump(personalKey, f)
        print("personal pw hash saved at ../keyBag/personalKey.pkl")
except Exception as e:
    print("Error during hashing:", str(e))
    print("personal hash:", personalKey)