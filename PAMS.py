
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
import webbrowser

import pyotp
# generate random integer values
from random import seed
from random import randint
# seed random number generator
seed(1)

import requests
from requests.structures import CaseInsensitiveDict

url = "http://localhost:9999/api/v1/mintNFT/1"

# secret key (seed)
SECRET_KEY = "base32topsecret7"

# initialize the TOTP generator with a specific configuration



curve = secp256k1

counter = 1

class NFT:
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
    def __init__(self, intervalTime=None, addSCV=None, urlMint=None, urlGet=None, urlOP=None):
        self.totp = pyotp.TOTP(SECRET_KEY, digest=sha256, digits=6, interval=30 or intervalTime)
        self.urlMint = "http://143.248.55.55:9999/api/v1/mintNFT/" or urlMint
        self.urlGet = "http://143.248.55.55:9999/api/v1/getNFT/" or urlGet
        self.urlOPD = "https://plus.codes/" or urlOP
        self.curve = secp256k1
        self.addSCV = addSCV or "0x7e09e481f2cc36d201bde90c86fc7f0838aaf36d"
        self.token = 0
        self.blockNumber = 00000000
        self.uuidStr = "NULL"#str(uuid.UUID(int=rd.getrandbits(128)))#uuid.UUID(rd.getrandbits(128))) # uuid1()) 
        self.locationTagStr = "NULL" 
        self.nfcCardUIDStr = "NULL"
        self.verifyKey = "0x008a8c17242be7bc322d425284766ccf29d9369a4e11cd3b7b33e68ab7e6523ecf87e5ddc1dd96143fbda4641d87330451c4e2fddaef8c36d43e5e4491d5b00b"
        
    def getPinCode(self):
        return self.totp.now()

    def encodeLocationURL(self, locationStr):
        return urllib.parse.quote(locationStr)
        
    def decodeLocationURL(self, locationEncoded):
        return urllib.parse.unquote(locationEncoded)   

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

    def generateKeys(self, Secret=None):
        print("...............................REG........................................")
        secretStr = str(input("Enter Key Secret : "))
        reader = Reader()
        uid = reader.get_uid()
        proveKey = PrivateKey(int(sha3_512((str(uid) + secretStr).encode('utf-8')).hexdigest(),16))
        verifyKey = proveKey.publicKey() 
        return verifyKey.toString()

    def mintNFT(self, lt, vk, urlMint=None):
        id = str(randint(0, 99999999))
        urlbase = self.urlMint or urlMint 
        url = urlbase+id
        headers = CaseInsensitiveDict()
        headers["Content-Type"] = "application/json"
        data = ("|"+ lt + ","+ vk + ";") #'{"locationTag": lt, verifyKey": vk}'
        resp = requests.post(url, headers=headers, data=data)
        print(resp.status_code)
        return resp, id   

    def getNFT(self, id, urlGet=None):
        urlbase = self.urlGet or urlGet
        url = urlbase+id
        headers = CaseInsensitiveDict()
        headers["Content-Type"] = "application/json"
        resp = requests.get(url, headers=headers)
        print(resp.status_code)
        print("Got reponse : ",resp.content)
        data = dumps(resp.content.decode("utf-8")) #json.dumps(a)
        ltRaw,vkRaw = data.split(",")
        headerRaw, lt = ltRaw.split("|")
        vk, footerRaw = vkRaw.split(";")
        print("locationTag : ", lt)
        print("verifyKey   : ", vk)
        return lt,vk 
        

    def prove(self, challenge, secret=None):
        print("...............................PROVE........................................")
        secretStr = secret or str(input("Enter Key Secret : "))
        pinCode = self.getPinCode()#pinCode or str(input("Enter Key Secret : "))
        print("Generated PinCode : ",pinCode)
        # for i in range(3):
        #     password = totp.now()
        #     print(password)
        #     time.sleep(1)
        i = input("Enter Prove Password : ")
        key = str(int(sha256((i).encode('utf-8')).hexdigest(),16))[:32]
        k = bytes(key,encoding='utf8')
        aes = aesctr(k)
        rc = str(challenge) 
        #pk = PrivateKey.fromString(NFC_Card_User.proveKey, secp256k1)
        reader = Reader()
        uid = reader.get_uid()
        pk = PrivateKey(int(sha3_512((str(uid) + secretStr).encode('utf-8')).hexdigest(),16))
        signature = Ecdsa.sign(rc, pk)
        p = (rc + "," + signature.toBase64())
        print("challenge : ",rc)
        q = aes.encrypt(p)
        R = urllib.parse.quote(q.hex())
        
        return R
    
    def verify(self,R, NFTUser):
        print("...............................VERIFY........................................")
        #i = input("Enter Verify Password : ")
        pinCode = self.getPinCode()#pinCode or str(input("Enter Key Secret : "))
        print("Generated PinCode : ",pinCode)
        i = pinCode 
        print("Recovered PinCode : ",pinCode)
        key = str(int(sha256((str(i)).encode('utf-8')).hexdigest(),16))[:32]
        k = bytes(key,encoding='utf8')
        aes = aesctr(k)
        q = bytes.fromhex(urllib.parse.unquote(R))        
        try:
            p = aes.decrypt(q).decode('ascii')#bytes(str(q),encoding='utf8')).decode('ascii')
            #print("P : ",str(p))
            rc,proof = p.split(",")
            #print("rc : ", rc)
            #print("proof : ", proof)
            signature = Signature.fromBase64(proof)
            #print("Sig: ",signature._toString())
            #print("vk = ", NFTUser.verifyKey)
            vk0 = NFTUser.verifyKey
            print("verifyKey   : ", vk0)
            lt, vk = self.getNFT(rc)
            print("locationTag : ", lt)
            print("verifyKey   : ", vk)
            verifyKey =  PublicKey.fromString(vk)
            if (Ecdsa.verify(rc, signature, verifyKey)):
                flag = True
                print(flag)
                try:
                    locationOP = self.decodeLocationURL(lt)
                    print("Location Tag: ",locationOP)
                    locationURL = self.urlOPD + locationOP
                    print("The location URL is: ",locationURL)
                    webbrowser.open(locationURL)
                except:
                    print("Invalid Location !!!")
            else:
                flag = False
                print(flag)
            #return flag
        except:
            flag = False
            print("Verification Time is expired !!!")
            print(flag)
        return flag

def main():
    print("Main Program is Started........... !!!")
    # Write code Here
    urlMint = "http://localhost:9999/api/v1/mintNFT/"
    urlGet = "http://localhost:9999/api/v1/getNFT/"
    urlOPD = "https://plus.codes/8Q8999F8+J7"
    locationOP = "8Q8999F8+J7"
    #cardsRegistered = ["0x437DFB03", "0x0BC250F9" , "0x8346FC03", "0x9670FC03", "0xEB3EBB1F"]
    Alice = NIZKP(30)
    print("Location OP: ", locationOP)
    lt = Alice.encodeLocationURL(locationOP)
    vk = Alice.generateKeys()
    print("Location Tag: ",lt)
    resPost, id = Alice.mintNFT(lt,vk)
    #resGet = Alice.getNFT(id)
    NFTAlice = NFT(lt,vk)
    challenge = id#NFTAlice.blockNumber
    responseAlice = Alice.prove(challenge)
    print("AUTHENTICATION RESULT: ")
    if (Alice.verify(responseAlice, NFTAlice)):
        print("Passed !!!")
    else:
        print("Failed !!!")
   
    print("Main Program is Ended Successfully !!!")


if __name__ == '__main__':
    main()