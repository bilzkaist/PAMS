
from acr122u.nfc import *
from json import dumps
import base64
from datetime import datetime
import uuid
from cryptoLib.ellipticcurve.ecdsa import Ecdsa
from cryptoLib.ellipticcurve.privateKey import PrivateKey
from cryptoLib.ellipticcurve.curve import secp256k1, getCurveByOid
from cryptoLib.ellipticcurve.ecdsa import Ecdsa
from cryptoLib.ellipticcurve.privateKey import PrivateKey
from cryptoLib.ellipticcurve.publicKey import PublicKey
from hashlib import sha256, sha3_512, sha1, shake_128
from cryptoLib.ellipticcurve.signature import Signature
import time
from cryptoLib.ellipticcurve.math import Math
from cryptoLib.pyaes.aes import AES, Counter, AESModeOfOperationCTR as aesctr
import os
import random
import urllib.parse


curve = secp256k1

counter = 1

class mintNFT:
    def __init__(self, locationTag, verifyKey, inputLink = None):
        self.locationTag = locationTag
        self.verifyKey = verifyKey
        self.inputLink = inputLink
        self.blockNumber = 11229175

class NFC_Card:
    def __init__(self, proveKey, blockNumber):
        self.UID = "0x9670FC03" 
        self.proveKey = proveKey
        self.blockNumber = blockNumber

class NIZKP ():
    def __init__(self, addSCV=None):
        self.curve = secp256k1
        self.addSCV = addSCV or "0x7e09e481f2cc36d201bde90c86fc7f0838aaf36d"
        self.token = 0
        self.blockNumber = 00000000
        self.uuidStr = "NULL"#str(uuid.UUID(int=rd.getrandbits(128)))#uuid.UUID(rd.getrandbits(128))) # uuid1()) 
        self.locationTagStr = "NULL" 
        self.nfcCardUIDStr = "NULL"
        self.verifyKey = "0x008a8c17242be7bc322d425284766ccf29d9369a4e11cd3b7b33e68ab7e6523ecf87e5ddc1dd96143fbda4641d87330451c4e2fddaef8c36d43e5e4491d5b00b"
        

    def getLocationTag(self, locationOPStr):
        #print("With Location OP Code : ",locationOPStr)
        locationOP_string_bytes = locationOPStr.encode("ascii")  
        location_base64_bytes = base64.b64encode(locationOP_string_bytes)
        location_base64_string = location_base64_bytes.decode("ascii")
        #print(f"Location Encoded string: {location_base64_string}")
        return location_base64_string

    def getLocationOP(self, locationTagStr): 
        #print("With Location Tag Code : ",locationTagStr)   
        locationTag_base64_bytes = locationTagStr.encode("ascii")
        locationOP_bytes = base64.b64decode(locationTag_base64_bytes)
        locationOPStr = locationOP_bytes.decode("ascii")
        #print(f"Location Decoded string: {locationOPStr}")
        return locationOPStr

    def generateKeys(self, Number, locationOP, secret="Unknown", CardUUID=None):
        self.locationTagStr = self.getLocationTag(locationOP)
        secretStr = secret
        rd = random.Random()
        rd.seed(Number)
        self.uuidStr = CardUUID or str(uuid.UUID(int=rd.getrandbits(128)))
        proveKey = PrivateKey(int(sha256((secretStr + self.locationTagStr + self.uuidStr).encode('utf-8')).hexdigest(),16))
        verifyKey = proveKey.publicKey() 
        #print("vk : ", verifyKey.toString())
        return proveKey.toString(), verifyKey.toString(), self.locationTagStr

        
        

    def prove(self, NFC_Card_User):
        i = input("Enter Prove Password : ")
        key = str(int(sha256((str(i)).encode('utf-8')).hexdigest(),16))[:32]
        k = bytes(key,encoding='utf8')
        aes = aesctr(k)
        rc = str(NFC_Card_User.blockNumber) 
        pk = PrivateKey.fromString(NFC_Card_User.proveKey, secp256k1)
        signature = Ecdsa.sign(rc, pk)
        p = (rc + "," + signature.toBase64())
        #print("Proof : ",p)
        q = aes.encrypt(p)
        #print("Q = ",q)
        R = urllib.parse.quote(str(q))
        #print("response : ",R)
        return q 
    
    def verify(self,R, NFTUser):
        i = input("Enter Verify Password : ")
        key = str(int(sha256((str(i)).encode('utf-8')).hexdigest(),16))[:32]
        k = bytes(key,encoding='utf8')
        aes = aesctr(k)
        q = urllib.parse.unquote(R)
        #print("Q : ",str(q))
        #bytes(q,encoding='utf8')
        p = aes.decrypt(R).decode('ascii')#bytes(str(q),encoding='utf8')).decode('ascii')
        #print("P : ",str(p))
        rc,proof = p.split(",")
        #print("rc : ", rc)
        #print("proof : ", proof)
        signature = Signature.fromBase64(proof)
        #print("Sig: ",signature._toString())
        #print("vk = ", NFTUser.verifyKey)
        vk =  PublicKey.fromString(NFTUser.verifyKey)
        if (Ecdsa.verify(rc, signature, vk)):
            flag = True
            print(flag)
        else:
            flag = False
            print(flag)
        return flag

def main():
    print("Main Program is Started........... !!!")
    # Write code Here
    locationOP = "8Q8999F8+J799C6+V5"
    cardsRegistered = ["0x437DFB03", "0x0BC250F9" , "0x8346FC03", "0x9670FC03", "0xEB3EBB1F"]
    Alice = NIZKP()
    pk, vk, lt = Alice.generateKeys(Counter, locationOP)
    NFTAlice = mintNFT(lt,vk)
    NFC_Card_Alice = NFC_Card(pk,NFTAlice.blockNumber)
    responseAlice = Alice.prove(NFC_Card_Alice)
    if (Alice.verify(responseAlice,NFTAlice)):
        print("Passed !!!")
    else:
        print("Failed !!!")
   
    print("Main Program is Ended Successfully !!!")


if __name__ == '__main__':
    main()