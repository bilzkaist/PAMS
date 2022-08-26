from json import dumps
import base64
from datetime import datetime
import uuid
from cryptoLib.ellipticcurve.ecdsa import Ecdsa
from cryptoLib.ellipticcurve.privateKey import PrivateKey
from cryptoLib.ellipticcurve.curve import secp256k1, getCurveByOid
from cryptoLib.ellipticcurve.ecdsa import Ecdsa
from cryptoLib.ellipticcurve.privateKey import PrivateKey
from hashlib import sha256, sha3_512
from cryptoLib.ellipticcurve.signature import Signature
import time
from cryptoLib.ellipticcurve.math import Math
#from cryptoLib.pyaes import aes, AES
from cryptoLib.pyaes.aes import AES, Counter, AESModeOfOperationCTR as aesctr

#from cryptoLib.aes import aes
#import cryptoLib.pyaes.aes as aes
import os
# # Generate privateKey from PEM string
# privateKey = PrivateKey.fromPem("""
#     -----BEGIN EC PARAMETERS-----
#     BgUrgQQACg==
#     -----END EC PARAMETERS-----
#     -----BEGIN EC PRIVATE KEY-----
#     MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
#     oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
#     RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
#     -----END EC PRIVATE KEY-----
# """)

# # Create message from json
# message = dumps({
#     "transfers": [
#         {
#             "amount": 100000000,
#             "taxId": "594.739.480-42",
#             "name": "Daenerys Targaryen Stormborn",
#             "bankCode": "341",
#             "branchCode": "2201",
#             "accountNumber": "76543-8",
#             "tags": ["daenerys", "targaryen", "transfer-1-external-id"]
#         }
#     ]
# })

# signature = EcdsaLoc.sign(message, privateKey)

# # Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
# print(signature.toBase64())

# # To double check if the message matches the signature, do this:
# publicKey = privateKey.publicKey()

# print(EcdsaLoc.verify(message, signature, publicKey))

# print("\nStandard....\n")
# start_time = time.time()
# for i in range(0,1):
#     # Generate new Keys
#     privateKey = PrivateKey()
#     publicKey = privateKey.publicKey()

#     message = "My test message"


#     print("Iteration %d" % i)
#     # Generate Signature
#     signature = Ecdsa.sign(message, privateKey)

#     #print("Signature : ",signature.toBase64())
#     # To verify if the signature is valid
#     print(Ecdsa.verify(message, signature, publicKey))
# standardTime = (time.time() - start_time)    
# print("Done............................................................................................................................................................................")
standardTime = 1
curve = secp256k1
print("\nLocation....\n")
start_time = time.time()

for i in range(0,1):
    # Generate new Keys
    locationOP = "8Q8999F8+J799C6+V5"
    
    locationOP_string_bytes = locationOP.encode("ascii")
    
    location_base64_bytes = base64.b64encode(locationOP_string_bytes)
    location_base64_string = location_base64_bytes.decode("ascii")
    
    #print(f"Encoded string: {location_base64_string}")

    base64_bytes = location_base64_string.encode("ascii")
  
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")
    
    #print(f"Decoded string: {sample_string}")
    challenge =" Where AM I ?"
    idString = "\nID: " + str(uuid.uuid1())
    #print("Starting with ID : ",idString)
    userString = "\nUser: Bilal"
    locationString = "\nLocation : " + location_base64_string
    challengeString ="\nChallenge : " + challenge
    timeNowString = "\nTime : " +" "+ (datetime.now()).strftime("%H:%M:%S")+", " + datetime.today().strftime("%B %d, %Y")
    timeSpacePerson = idString + userString+locationString  + challengeString + timeNowString + "\n"
    print("timeSpacePerson = ", timeSpacePerson)
    hashed_key = sha3_512(timeSpacePerson.encode('utf-8')).hexdigest()
    print("Hash Key : ",hashed_key)
    Key = int(hashed_key,16)
    print("\nSecret : ",Key) 
    #modN = int(0xf10f3df7d17cf89ef10f3df7d17cf89ef10f3df7d17cf89ef10f3df7d17cf89e)
    modN  = int(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    modNL = int(0xffffffffffffffff)
    privateKey =  PrivateKey(Key)
    publicKey = privateKey.publicKey()
    print("PrivateKey  = ",privateKey.toString())
    print("PublicKey   = ",publicKey.toString())
    timeNowString2 = "\nTime : " +" "+ (datetime.now()).strftime("%H:%M:%S")+", " + datetime.today().strftime("%B %d, %Y")  
    privateKey2 =  PrivateKey(Key%modN)
    publicKey2 = privateKey2.publicKey()
    print("PrivateKey2 = ",privateKey2.toString())
    print("PublicKey2  = ",publicKey2.toString())
    message = timeSpacePerson
    for j in range(0,1):
        print("..................................................................")
        privateKey =  PrivateKey(Key)
        publicKey = privateKey.publicKey()
        print("PrivateKey  = ",privateKey.toString())
        print("PublicKey   = ",publicKey.toString())
        timeNowString2 = "\nTime : " +" "+ (datetime.now()).strftime("%H:%M:%S")+", " + datetime.today().strftime("%B %d, %Y")  
        privateKey2 =  PrivateKey(Key%int(sha256((str(j)+ timeNowString2).encode('utf-8')).hexdigest(),16))
        publicKey2 = privateKey2.publicKey()
        print("PrivateKey2 = ",privateKey2.toString())
        print("PublicKey2  = ",publicKey2.toString())
        print("Iteration j = %d" %j)
        # Generate Signature
        signature = Ecdsa.sign(message, privateKey)
        signature2 = Ecdsa.sign(message, privateKey2)
        response = message + signature.toBase64() + publicKey.toPem()
        flag = False
        print("Signature  : ",signature.toBase64())
        print("Signature2 : ",signature2.toBase64())
    #   print("Prover Send this response : ",response)
        # To verify if the signature is valid
        print("Verify 1  Results : ")
        if (Ecdsa.verify(message, signature, publicKey)):
            flag = True
            print(flag)
        else:
            print(flag)
        print("Verify 2  Results : ")
        if (Ecdsa.verify(message, signature2, publicKey2)):
            flag = True
            print(flag)
        else:
            print(flag)
        print("..................................................................")
    privateKeyAlice = privateKey
    publicKeyAlice  = publicKey
    
    privateKeyBob = privateKey2
    publicKeyBob  = publicKey2
    # if (i==0):
    #     privateKeyAlice = privateKey
    #     publicKeyAlice  = publicKey
    # else:
    #     privateKeyBob = privateKey
    #     publicKeyBob  = publicKey
    secretKey = Math.multiply(publicKey.point, privateKey.secret % curve.N, N=curve.N, A=curve.A, P=curve.P)
    print("\nSecret Key : ",secretKey)
    print("PrivateKey = ",privateKey.toString())
    print("PublicKey  = ",publicKey.toString())
    #result = (remote_public_key.pubkey.point * self.private_key.privkey.secret_multiplier)
    #u1 = Math.multiply(curve.G, n=(numberMessage * inv) % curve.N, N=curve.N, A=curve.A, P=curve.P)
    #u2 = Math.multiply(publicKey.point, n=(r * inv) % curve.N, N=curve.N, A=curve.A, P=curve.P)
    #v = Math.add(u1, u2, A=curve.A, P=curve.P)


    
    

    print("Iteration %d" % i)
    # Generate Signature
    signature = Ecdsa.sign(message, privateKey)
    signature2 = Ecdsa.sign(message, privateKey2)
    response = message + signature.toBase64() + publicKey.toPem()
    flag = False
    print("Signature  : ",signature.toBase64())
    print("Signature2 : ",signature2.toBase64())
 #   print("Prover Send this response : ",response)
    # To verify if the signature is valid
    print("Verify 1  Results : ")
    if (Ecdsa.verify(message, signature, publicKey)):
        flag = True
        print(flag)
    else:
        print(flag)
    print("Verify 2  Results : ")
    if (Ecdsa.verify(message, signature2, publicKey2)):
        flag = True
        print(flag)
    else:
        print(flag)
LocationTime = (time.time() - start_time)    
print("Done............................................................................................................................................................................")
print("Standard--- %s seconds ---" % standardTime)
print("Location--- %s seconds ---" % LocationTime)
print("Optimazation = %s ", (1-LocationTime/standardTime) *100)
sharedSecretKeyAlice = Math.multiply(publicKeyBob.point, privateKeyAlice.secret % curve.N, N=curve.N, A=curve.A, P=curve.P)
print("\nShared Secret Key Alice : ",sharedSecretKeyAlice)
sharedSecretKeyBob = Math.multiply(publicKeyAlice.point, privateKeyBob.secret % curve.N, N=curve.N, A=curve.A, P=curve.P)
print("\nShared Secret Key Bob   : ",sharedSecretKeyBob)


key = os.urandom(32)
iv = os.urandom(16)
secretKeyAlice = str(sharedSecretKeyAlice.x)[:32]
print("Secret Key Alice : ", secretKeyAlice)
secretKeyBob = str(sharedSecretKeyBob.x)[:32]
print("Secret Key Bob   : ", secretKeyBob)
#encrypted = aes.AES(key).encrypt_ctr(b'Attack at dawn', iv)
#print(aes.AES(key).decrypt_ctr(encrypted, iv))

keyAlice = bytes(secretKeyBob,encoding='utf8')
keyBob   = bytes(secretKeyBob,encoding='utf8')

# A 256 bit (32 byte) key
#key = "This_key_for_demo_purposes_only!"

# For some modes of operation we need a random initialization vector
# of 16 bytes
#iv = "InitializationVe"

#aes = AESModeOfOperationCTR(keyAlice)
aes = aesctr(keyAlice)
plaintext = "Text may be any length you wish, no padding is required"
ciphertext = aes.encrypt(plaintext)

# '''\xb6\x99\x10=\xa4\x96\x88\xd1\x89\x1co\xe6\x1d\xef;\x11\x03\xe3\xee
#    \xa9V?wY\xbfe\xcdO\xe3\xdf\x9dV\x19\xe5\x8dk\x9fh\xb87>\xdb\xa3\xd6
#    \x86\xf4\xbd\xb0\x97\xf1\t\x02\xe9 \xed'''
print(repr(ciphertext))

# The counter mode of operation maintains state, so decryption requires
# a new instance be created
aes = aesctr(keyBob)
decrypted = aes.decrypt(ciphertext).decode('ascii')


print("Decryption completed : ", decrypted)
# True
print(decrypted == plaintext)

# To use a custom initial value
counter = Counter(initial_value = 100)
aes = aesctr(key, counter = counter)
ciphertext = aes.encrypt(plaintext)

# '''WZ\x844\x02\xbfoY\x1f\x12\xa6\xce\x03\x82Ei)\xf6\x97mX\x86\xe3\x9d
#    _1\xdd\xbd\x87\xb5\xccEM_4\x01$\xa6\x81\x0b\xd5\x04\xd7Al\x07\xe5
#    \xb2\x0e\\\x0f\x00\x13,\x07'''
print(repr(ciphertext))