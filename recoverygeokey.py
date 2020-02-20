# https://github.com/zeltsi/Bitpy/blob/master/Utils/keyUtils/keys.py

# Copyright (C) Philipp Andreas Angele - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Philipp Andreas Angele <philipp_angele@gmx.de>, June 2019
import bcrypt
import argparse
import binascii
import base58
import struct
import hashlib
import codecs

from ecdsa import SigningKey, SECP256k1

from Crypto.Cipher import AES
from clbfcrypt import clbflib

from threading import Thread


blib = clbflib()

enginecount = blib.getengincount()
print(enginecount)

liblist = []
liblist.append(blib)

for i in range(1, enginecount):
    blibtmp = clbflib()
    blibtmp.setchanel(i)
    liblist.append(blibtmp)

class Params(object):
    def __init__(self, pas=None):
        self.pas = pas
    def __call__(self, x):
            return self.pas[0:31]

def inttohex(nval):
    #shex = hex((nval + (1 << 32)) % (1 << 32))
    #shex = shex[2:]
    
    shex = struct.pack("<I", (nval + 2**32) % 2**32).encode('hex')
    
    return shex
    
def geoinfotohex(lat,long):
    
    nlat = int(abs(float(lat)) * 1000000000.0)
    nlong = int(abs(float(long)) * 1000000000.0)
    
    if lat < 0:
        nlat = nlat * -1
    if long < 0:
        nlong = nlong * -1
        
    shex = inttohex(nlat) + inttohex(nlong)    
    return shex
    
def bfhashtohex(bfhash):    
    stemp = bfhash
    #print("stemp " + stemp)
    #print(len(stemp))  
    
    keyval = stemp[:16]    
    #print("keyval " + keyval)
    #print(len(keyval))  
    
    inval = stemp[16:32]    
    #print("inval " + inval)
    #print(len(inval))  
    
    cipher = AES.new(keyval, AES.MODE_ECB)
    outval = cipher.encrypt(inval)

    
    n1 = int(codecs.encode(outval[0:4], 'hex'), 16)
    n2 = int(codecs.encode(outval[4:8], 'hex'), 16)
    n3 = int(codecs.encode(outval[8:12], 'hex'), 16)
    n4 = int(codecs.encode(outval[12:16], 'hex'), 16)

    
    n1 = n1 + n2;
    n3 = n3 + n4;    
    shex = inttohex(n1) + inttohex(n3)
    
    return shex    
    
def wif(sk):
    # WIF
    # https://en.bitcoin.it/wiki/Wallet_import_format

    # (2)
    extended_key = bytearray(b'\x80') + sk.to_string()

    # (3)
    hasher_sha256 = hashlib.sha256()
    hasher_sha256.update(extended_key)
    hashed = hasher_sha256.digest()

    # (4)
    hasher_sha256_2 = hashlib.sha256()
    hasher_sha256_2.update(hashed)
    hashed_2 = hasher_sha256_2.digest()

    # (5)
    checksum = hashed_2[0:4]

    # (6)
    extended_key_and_checksum = extended_key + hashed_2[0:4]

    # (7)
    return base58.b58encode(bytes(extended_key_and_checksum))

def bchr(s):
    return bytes([s])


def generatecoinkey(ablib, password, gps, nround, sprivatekey, resultlist):

    if len(password) == 0:
        return
    
    if len(gps) == 0:
        return
        
    centlatlong = gps.split(",")
    
    if len(centlatlong) != 2:
        print("invalid gps argument")
        return
            
            
    salt = geoinfotohex(centlatlong[0],centlatlong[1])
            
    hashed_pw = ablib.process(password, salt, nround)
    
    #32byte to 16 byte
    #slatsec = bfhashtohex(hashed_pw)    
    hashed_pw32 = hashed_pw[29:60] + "P" #Philipp
    #print("hashed_pw32: " + hashed_pw32)
    
    slatsec = bfhashtohex(hashed_pw32)    
    
    hashed_gps = ablib.process(gps, slatsec, nround)
    private_key = hashed_gps[29:60] + "O" #Oscar
    #print("hashed_gps32: " + private_key)    
    
    #print("hashed_pw            : " + binascii.hexlify(hashed_pw).decode("utf-8"))
    #print("private_key          : " + binascii.hexlify(private_key).decode("utf-8"))

    sk = SigningKey.generate(curve=SECP256k1, entropy=Params(pas=private_key))
    vk = sk.get_verifying_key()

    # (0)
    privateKey0 = sk.to_string()
    privateKey = binascii.b2a_hex(privateKey0)
    
    print("private_key          : " + privateKey)
    if privateKey == sprivatekey:     
        ressuccess =  password + " " + gps
        resultlist.append(ressuccess)
        
    return
 #0057722e4f456371587a41574136684f514b3538773770546b714869396d5a66
 #python recoverygeokey.py --input geoinfo.txt --privatekey 00415a744255453332364c574f5a6a4d78314c545966747a5352636263583133 --round 64
 
def main():
    parser = argparse.ArgumentParser(description='Generate key.')
    parser.add_argument('--input', type=str, help='password and geoinfolist')
    parser.add_argument('--privatekey', type=str, help='bitcoin private key')
    parser.add_argument('--round', type=int, help='bcrypt lop round to use')
    
    args = parser.parse_args()

    #password=bytes(args.password, "utf8")
    sinfile = args.input
    #gps=bytes(args.gps, "utf8")
    sprivatekey = args.privatekey
    nround  = args.round
    
    recoverysuccess = 0
    pwgpssuccess = ""
    
    try:
        finfile = open(sinfile, 'r')
        
# for simplicity in testing the rounds are set to 32 rounds = 2^5 while the recommended production rounds are 2^16, 65536 rounds.
# this results in about 1 key every 500 ms on a state of the art nvidia but takes about 4 minutes on a single threaded cpu process.
#hashed_pw = bcrypt.kdf(password=password, salt=gps, desired_key_bytes=32, rounds=32)
#private_key = bcrypt.kdf(password=gps, salt=hashed_pw, desired_key_bytes=32, rounds=32)
#blib = clbflib()
#hash = blib.process("password", "16bytesalt", round)
        bRun = True
        while bRun:
        
            procs = []
            resultlist = []
            for index in range(0, enginecount):
            
                line = finfile.readline()
                
                if len(line) == 0:
                    bRun = False
                    password = ""
                    gps = ""
                else:
                    line = line.replace ("\n","")
                    pwgps = line.split(" ")
                    if len(pwgps) == 2:
                        password = pwgps[0]
                        gps = pwgps[1]
                    else:
                        password = ""
                        gps = ""

                proc = Thread(target=generatecoinkey, args=(liblist[index],password,gps,nround,sprivatekey,resultlist)) 
                procs.append(proc) 
                proc.start()   
                
            for proc in procs: 
                proc.join()
                
            for strres in resultlist: 
                if len(strres) > 0:
                    pwgpssuccess = strres
                    recoverysuccess = 1
                    bRun = False
                    
    
            #---------------------------------------------------------
            #line = finfile.readline()            
            #if len(line) == 0:
            #    break
            #pwgps = line.split(" ")
            #if len(pwgps) != 2:
            #    continue
            #password = pwgps[0]
            #gps = pwgps[1]

            #resultlist = []
            #generatecoinkey(0, password, gps, nround, resultlist)
            
            #if len(resultlist) > 0:
            #    foutfile.write(resultlist[0])
            #----------------------------------------------------------
        
        finfile.close()              
        
    except IOError:
        print("\n-----------------\nCould not open  geoinfo list file!")
    
    print("\n")
    print("-----------------")
    if recoverysuccess == 1:        
        print("Success recovery!")
        print(pwgpssuccess)        
    elif recoverysuccess == 0:
        print("Can not find matching infomation!")
        
    print("-----------------\n")
      

if __name__== "__main__":
    main()