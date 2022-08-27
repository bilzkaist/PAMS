
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
from hashlib import sha256, sha3_512, sha1, shake_128
from cryptoLib.ellipticcurve.signature import Signature
import time
from cryptoLib.ellipticcurve.math import Math
from cryptoLib.pyaes.aes import AES, Counter, AESModeOfOperationCTR as aesctr
import os
import random




mintNumber = 1

class mintNFT:
    def __init__(self, locationTag, verifyKey, inputLink = None):
        self.locationTag = locationTag
        self.verifyKey = verifyKey
        self.inputLink = inputLink

class NFC_Card:
    def __init__(self, proveKey, blockNumber):
        self.UID = "0x9670FC03" 
        self.proveKey = proveKey
        self.blockNumber = blockNumber

class PAMS ():
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

    def write(self, r, position, number, data):
        while number >= 16:
            self.write_16(r, position, 16, data)
            number -= 16
            position += 1


    def write_16(self, r, position, number, data):
        r.update_binary_blocks(position, number, data)


    def read(self, r, position, number):
        result = []
        while number >= 16:
            result.append(self.read_16(r, position, 16))
            number -= 16
            position += 1
        return result


    def read_16(self, r, position, number):
        return r.read_binary_blocks(position, number)

    def splitByte(self, b): 
        lowerMask = b'\x0F' 
        lowerHalf = bytes(b & lowerMask[0])[0] 
        upperMask = b'\xF0' 
        upperHalf = bytes(b & upperMask[0])[0] 
        upperHalf = upperHalf >> 4 
        return [upperHalf,lowerHalf]

    def generateKeys(self, mintNumber, locationOP, secret="Unknown", CardUUID=None):
        self.locationTagStr = self.getLocationTag(locationOP)
        secretStr = secret
        rd = random.Random()
        rd.seed(mintNumber)
        self.uuidStr = CardUUID or str(uuid.UUID(int=rd.getrandbits(128)))
        proveKey = PrivateKey(int(sha256((secretStr + self.locationTagStr + self.uuidStr).encode('utf-8')).hexdigest(),16))
        verifyKey = proveKey.publicKey() 
        return proveKey, verifyKey
    #     proveKeyStr = proveKey.toString()
    #     print("ProveKEY String : [",proveKeyStr,"]")
    #     proveKeyLen = len(proveKeyStr)
    #     print("proveKey String : [",proveKeyStr,"] (",proveKeyLen,")")
    #     pk1 = proveKeyStr[0:31]
    #     pk2 = proveKeyStr[32:63]
    #     print(" pks : ", pk1, "-",pk2)
    #     b1 = os.urandom(16)
    #     b2 = os.urandom(16)

    #     print("b1 and b2 : ", b1, "|", b2)

    #    # proveKeyByte01 = bytes.fromhex(hex(proveKeyStr[0:31]))
    #    # proveKeyByte02 = bytes.fromhex(hex(proveKeyStr[32:63]))
    #     proveKeyByte = bytes.fromhex(proveKey.toString())
    #    # [proveKeyByte01, proveKeyByte02] = self.splitByte(proveKeyByte)
    #     print("Byte ProveKey : ", (proveKeyByte))# + proveKeyByte01))
    #     print("Proving Key : ", proveKey.toString(), " with size : ", len(proveKey.toString()))
    #     print("Verify Key  : ", verifyKey.toString())
    #     self.blocknumber = 11229175#mintNFT()
    #     #reader = Reader()
    #    # reader.load_authentication_data(0x01, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    #     #reader.authentication(0x00, 0x61, 0x01)
    #     #print("Proving Key : ", proveKey.toString())
    #    # self.write(reader, 0x01, 0x20, [cardKeyByte [i] for i in range(16)])
    #     #self.write(reader, 0x01, 0x10, [proveKeyByte01[i] for i in range(16)])
    #     #self.write(reader, 0x01, 0x20, [proveKeyByte02[i] for i in range(16)])
    #    # self.write(reader, 0x01, 0x40, [b1[i] for i in range(16)])
    #    # self.write(reader, 0x01, 0x50, [b2[i] for i in range(16)])
    #    # print(self.read(reader, 0x01, 0x20))
        
        

    def prover(self, challenge):
        signature = Ecdsa.sign(challenge, privateKey)
        response = challenge + signature
        return response    
    
    def verify(self, response, signature):
        if (Ecdsa.verify(response, signature, publicKey)):
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
    A = PAMS()
    A.mint(mintNumber, locationOP)
    print("Main Program is Ended Successfully !!!")


if __name__ == '__main__':
    main()