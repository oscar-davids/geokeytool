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
import json
import requests
import os
import sys
import sqlite3
import subprocess
import math
#import tqdm



from ecdsa import SigningKey, SECP256k1

from Crypto.Cipher import AES
from clbfcrypt import clbflib

from threading import Thread
from multiprocessing import Process, Queue

modecreate = True

blib = clbflib()

enginecount = blib.getengincount()
print("\nDevice Count : " + str(enginecount))

liblist = []
liblist.append(blib)

for i in range(1, enginecount):
    blibtmp = clbflib()
    blibtmp.setchanel(i)    
    liblist.append(blibtmp)

for i in range(0, enginecount):
    print("Device#" + str(i+1) + " Thread Count : " + str(liblist[i].getpower()))
    
sbalancedb = "./dbbalance.db"

        
dbconnectlist = []    
for i in range(0, enginecount):
    conn = sqlite3.connect(sbalancedb)    
    dbconnectlist.append(conn)

class Params(object):
    def __init__(self, pas=None):
        self.pas = pas
    def __call__(self, x):
            return self.pas[0:31]

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s    %s\r' % (bar, percents, '%', status))
    sys.stdout.flush()
    
def checkdbpath(sdbpath):
    if os.path.isfile(sdbpath) == False:
        print("There is no coin UTXO database.")
        print("To build a UTXO database, Please confirm bitcoin is installed.")
        print("-----Starting build UTXO database.-----")
        print("-----It takes more 30 minutes.-----")
        return False
        
    return True

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


def generatecoinkey(brecovery, ablib, password, gps, nround, bdebugflag,resultlist):

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

    # (1)
    pubkey = bytearray(b'\x04') + vk.to_string()

    # (2)
    hasher_sha256 = hashlib.sha256()
    hasher_sha256.update(pubkey)
    hashed_sha256 = hasher_sha256.digest()

    # (3)
    hasher_ripemd160 = hashlib.new('ripemd160')
    hasher_ripemd160.update(hashed_sha256)
    hashed_ripemd160 = hasher_ripemd160.digest()

    # (4)
    main_network_version = bytearray(b'\x00')
    hashed_ripemd160_with_version = main_network_version + hashed_ripemd160

    # (5)
    hasher_sha256 = hashlib.sha256()
    hasher_sha256.update(hashed_ripemd160_with_version)
    hashed_ripemd160_with_version_sha256 = hasher_sha256.digest()

    # (6)
    hasher_sha256 = hashlib.sha256()
    hasher_sha256.update(hashed_ripemd160_with_version_sha256)
    hashed_ripemd160_with_version_roundtwo_sha256 = hasher_sha256.digest()

    # (7)
    checksum=hashed_ripemd160_with_version_roundtwo_sha256[0:4]

    # (8)
    bitcoin_address =  hashed_ripemd160_with_version + checksum

    # (9)
    bitcoin_address_base58 = base58.b58encode(bytes(bitcoin_address))

    privateKey = binascii.b2a_hex(privateKey0)
    publicKey =  binascii.hexlify(pubkey).decode("utf-8")
    bitcoinaddress = binascii.hexlify(bitcoin_address).decode("utf-8")
    bitcoinaddressbase58 = bitcoin_address_base58.decode("utf-8")
    walletinputformat = wif(sk).decode("utf-8")
    
    
    #print("private key            : " + privateKey)
    # print("public key             : " + publicKey)
    # print("public key sha256: " + binascii.hexlify(hashed_sha256).decode("utf-8"))
    # print("public key ripemd160: " + binascii.hexlify(hashed_ripemd160).decode("utf-8"))
    # print("public key ripemd160 and version: " + binascii.hexlify(hashed_ripemd160_with_version).decode("utf-8"))
    # print("public key ripemd160 and version sha256: " + binascii.hexlify(hashed_ripemd160_with_version_sha256).decode("utf-8"))
    # print("public key ripemd160 and version sha256 round two: " + binascii.hexlify(hashed_ripemd160_with_version_roundtwo_sha256).decode("utf-8"))
    # print("public key checksum: " + binascii.hexlify(checksum).decode("utf-8"))           
    ##print("bitcoin address: " + bitcoinaddress)
    if brecovery == True and bdebugflag == True:
        print("bitcoin address base58 : " + bitcoinaddressbase58)            
    #print("wif: " + walletinputformat)
    
    jsonstr = "{" + "\n" + '''"password":''' + '''"''' + password + '''",''' + " \n"
    jsonstr += '''"gps":''' + '''"''' + gps + '''",''' + " \n"
    jsonstr += '''"bcrypt output1":''' + '''"''' + hashed_pw + '''",''' + " \n"
    jsonstr += '''"bcrypt output2":''' + '''"''' + hashed_gps + '''",''' + " \n"
    jsonstr += '''"private key":''' + '''"''' + privateKey + '''",''' + " \n"
    jsonstr += '''"public key":'''+ '''"'''  + publicKey + '''",''' + " \n"
    jsonstr += '''"bitcoin address":'''+ '''"'''  + bitcoinaddress + '''",''' + " \n" 
    jsonstr += '''"bitcoin address base58":'''+ '''"'''  + bitcoinaddressbase58 + '''",''' + " \n"
    jsonstr += '''"wif":''' +  '''"''' + walletinputformat + '''"''' + "\n" + "}"+ "\n"    
    resultlist.append(jsonstr)
    
    return

def revoverycoinkey(brecovery, ablib, password, onegpslist, nround, bdebugflag,resultlist):

    if len(password) == 0:
        return
    
    npower = len(onegpslist)
    
    if npower == 0:
        return
    
    ablib.reset_device()
    
    for i in range(0, npower):
        gps = onegpslist[i]
        centlatlong = gps.split(",")
        if len(centlatlong) == 2:
            salt = geoinfotohex(centlatlong[0],centlatlong[1])
        else:
            salt = "0123456789"
        ablib.add_data(i,password,salt)
    
    ablib.runprocess(nround)
    
    pwhashlist = []
    pwhashlist32 = []
    saltseclist = []
    for i in range(0, npower):
        pwtemp = ablib.get_data(i)
        pwhashlist.append(pwtemp)
        
        hashed_pw32 = pwtemp[29:60] + "P"         
        saltsec = bfhashtohex(hashed_pw32)
        
        pwhashlist32.append(hashed_pw32) 
        saltseclist.append(saltsec)
            
    ablib.reset_device()    
    
    for i in range(0, npower):
        ablib.add_data(i,onegpslist[i],saltseclist[i])

    ablib.runprocess(nround)
    
    gpshashlist = []
    ecsdprikeylist = []
    for i in range(0, npower):
        gpshashtemp = ablib.get_data(i)
        gpshashlist.append(gpshashtemp)
        private_key = gpshashtemp[29:60] + "O" #Oscar
        ecsdprikeylist.append(private_key)
    
    
    for i in range(0, npower):
        hashed_pw = pwhashlist[i]
        hashed_gps = gpshashlist[i]
        private_key = ecsdprikeylist[i]    

        sk = SigningKey.generate(curve=SECP256k1, entropy=Params(pas=private_key))
        vk = sk.get_verifying_key()

        # (0)
        privateKey0 = sk.to_string()

        # (1)
        pubkey = bytearray(b'\x04') + vk.to_string()

        # (2)
        hasher_sha256 = hashlib.sha256()
        hasher_sha256.update(pubkey)
        hashed_sha256 = hasher_sha256.digest()

        # (3)
        hasher_ripemd160 = hashlib.new('ripemd160')
        hasher_ripemd160.update(hashed_sha256)
        hashed_ripemd160 = hasher_ripemd160.digest()

        # (4)
        main_network_version = bytearray(b'\x00')
        hashed_ripemd160_with_version = main_network_version + hashed_ripemd160

        # (5)
        hasher_sha256 = hashlib.sha256()
        hasher_sha256.update(hashed_ripemd160_with_version)
        hashed_ripemd160_with_version_sha256 = hasher_sha256.digest()

        # (6)
        hasher_sha256 = hashlib.sha256()
        hasher_sha256.update(hashed_ripemd160_with_version_sha256)
        hashed_ripemd160_with_version_roundtwo_sha256 = hasher_sha256.digest()

        # (7)
        checksum=hashed_ripemd160_with_version_roundtwo_sha256[0:4]

        # (8)
        bitcoin_address =  hashed_ripemd160_with_version + checksum

        # (9)
        bitcoin_address_base58 = base58.b58encode(bytes(bitcoin_address))

        privateKey = binascii.b2a_hex(privateKey0)
        publicKey =  binascii.hexlify(pubkey).decode("utf-8")
        bitcoinaddress = binascii.hexlify(bitcoin_address).decode("utf-8")
        bitcoinaddressbase58 = bitcoin_address_base58.decode("utf-8")
        walletinputformat = wif(sk).decode("utf-8")
        
        
        #print("private key            : " + privateKey)
        # print("public key             : " + publicKey)
        # print("public key sha256: " + binascii.hexlify(hashed_sha256).decode("utf-8"))
        # print("public key ripemd160: " + binascii.hexlify(hashed_ripemd160).decode("utf-8"))
        # print("public key ripemd160 and version: " + binascii.hexlify(hashed_ripemd160_with_version).decode("utf-8"))
        # print("public key ripemd160 and version sha256: " + binascii.hexlify(hashed_ripemd160_with_version_sha256).decode("utf-8"))
        # print("public key ripemd160 and version sha256 round two: " + binascii.hexlify(hashed_ripemd160_with_version_roundtwo_sha256).decode("utf-8"))
        # print("public key checksum: " + binascii.hexlify(checksum).decode("utf-8"))           
        ##print("bitcoin address: " + bitcoinaddress)
        if brecovery == True and bdebugflag == True:
            print("bitcoin address base58 : " + bitcoinaddressbase58)            
        #print("wif: " + walletinputformat)
        
        jsonstr = "{" + "\n" + '''"password":''' + '''"''' + password + '''",''' + " \n"
        jsonstr += '''"gps":''' + '''"''' + gps + '''",''' + " \n"
        jsonstr += '''"bcrypt output1":''' + '''"''' + hashed_pw + '''",''' + " \n"
        jsonstr += '''"bcrypt output2":''' + '''"''' + hashed_gps + '''",''' + " \n"
        jsonstr += '''"private key":''' + '''"''' + privateKey + '''",''' + " \n"
        jsonstr += '''"public key":'''+ '''"'''  + publicKey + '''",''' + " \n"
        jsonstr += '''"bitcoin address":'''+ '''"'''  + bitcoinaddress + '''",''' + " \n" 
        jsonstr += '''"bitcoin address base58":'''+ '''"'''  + bitcoinaddressbase58 + '''",''' + " \n"
        jsonstr += '''"wif":''' +  '''"''' + walletinputformat + '''"''' + "\n" + "}"+ "\n"    
        resultlist.append(jsonstr)
    
    return
    
def getgpsarray(cenlat,cenlong,iterator,stepdgree,gpslist):
    for i in range(-iterator, iterator + 1):
        for j in range(-iterator, iterator + 1):
            lat = cenlat + i * stepdgree
            long = cenlong + j * stepdgree

            strlat = '%.08f' % lat
            strlong = '%.08f' % long

            if lat > 0.0:
                strlat = "+" + strlat
            if long > 0.0:
                strlong = "+" + strlong

            strlatlong = strlat + "," + strlong
            gpslist.append(strlatlong)

            
def gengpsarray(gps,unit,rarius,gpslist):

    centlatlong = gps.split(",")
    if len(centlatlong) != 2:
        print("invalid gps argument")
        return

    cenlat = float(centlatlong[0])
    cenlong = float(centlatlong[1])

    
    scanunit =  unit

    #earth mean radius mm
    #637813700
    earthradius = 6371008800
    #calculate real degree unit for argument unit
    earthtotallen = math.pi * 2.0 * earthradius
    #calc square step
    stepdgreepermm = 360.0 / earthtotallen
    
    searchradiusmm = rarius * 1000
    
    if scanunit == "m" or scanunit == "all":
        stepdgree = 0.00001000
        iterator = int(searchradiusmm/1000)
        getgpsarray(cenlat,cenlong,iterator,stepdgree,gpslist)
        
    elif scanunit == "dm" or scanunit == "all":
        stepdgree = 0.00000100
        iterator = int(searchradiusmm/100)
        getgpsarray(cenlat,cenlong,iterator,stepdgree,gpslist)
        
    elif scanunit == "cm" or scanunit == "all":
        stepdgree = 0.00000010
        iterator = int(searchradiusmm/10)        
        getgpsarray(cenlat,cenlong,iterator,stepdgree,gpslist)
        
    if scanunit == "mm" or scanunit == "all":
        #https://en.wikipedia.org/wiki/Decimal_degrees
        stepdgree = 0.00000001
        iterator = int(searchradiusmm)
        getgpsarray(cenlat,cenlong,iterator,stepdgree,gpslist)        
    
    #for i in range(-iterator, iterator + 1):
    #    for j in range(-iterator, iterator + 1):
    #        lat = cenlat + i * stepdgree
    #        long = cenlong + j * stepdgree
    #
    #        strlat = '%.08f' % lat
    #        strlong = '%.08f' % long
    #
    #        if lat > 0.0:
    #            strlat = "+" + strlat
    #        if long > 0.0:
    #            strlong = "+" + strlong
    #
    #        strlatlong = strlat + "," + strlong
    #        gpslist.append(strlatlong)
    #        #print(strlatlong)
    #        #strline = password + " " + strlatlong + '\n'         
            
                

#python geokeys.py --create --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit dm
#python geokeys.py --recover --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit dm --radius 0.5
#python geokeys.py --recover --password donotqwerty --gps +40.73150390,-73.96328405 --round 64 --unit all --radius 0.5 --debug
    
def main():
    parser = argparse.ArgumentParser(description='Generate and recovery geocoin key.')
    #parser.add_argument('--create', type=bool, default=False, help='Create flag')
    #parser.add_argument('--recover', type=bool, default=True, help='Recovery flag')
    parser.add_argument('--create', dest='accumulate', action='store_const',const=True ,default=False, help='Recovery flag')
    parser.add_argument('--recover', dest='accumulate', action='store_const',const=False ,default=True, help='Recovery flag')
   
    parser.add_argument('--password', type=str, help='a password')
    parser.add_argument('--gps', type=str, help='gps coordinates to use')
    parser.add_argument('--round', type=int, default=1024, help='bcrypt lop round to use')
    parser.add_argument('--unit', type=str, default='dm',help='search unit to use(m dm cm mm all)')
    parser.add_argument('--radius', type=float,default=0.5, help='search radius(m) to use')
    
    parser.add_argument('--debug', dest='debugflag', action='store_const',const=True ,default=False, help='Debug flag')    
    
    args = parser.parse_args()

    if args.accumulate:
        print("Create Geokey!\n")
        modecreate = True
    else:
        print("Recovery Geokey!\n")
        modecreate = False
    
    bdebugflag = False
    if args.debugflag:
        bdebugflag = True
        
    nround  = args.round
    password = args.password    
    radius = args.radius  
    
    recoverylist = []
    
    if modecreate == True:
        resultlist = []
        foutfile = open(password + "_key.txt", 'w')
        generatecoinkey(False, liblist[0],args.password,args.gps,nround,bdebugflag,resultlist)
        for strres in resultlist: 
                if len(strres) > 0:
                    print(strres)
                    foutfile.write(strres)
                    
        print("Complete!\n")
    else:
        if checkdbpath(sbalancedb) == False:
            return
            
        try:            
            foutfile = open(password + "_recovery.txt", 'w')
            
            gpslist = []
            gengpsarray(args.gps,args.unit,args.radius,gpslist)
            searchcount = len(gpslist)
            
            conn = sqlite3.connect(sbalancedb)
            dc = conn.cursor()
            
            if bdebugflag == True:
                foutdebugfile = open(password + "_keydebug.txt", 'w')                
            else:
                print("Wait while recovering...\n")
                            
            i = 0       
            while i < searchcount:  
            #for i in tqdm(range(0, searchcount)):
                resultlist = []
                procs = []
            
                for index in range(0, enginecount):
                    nmaxpower = liblist[index].getpower()
                    gpsonelist = []
                    for gidx in range(0, nmaxpower):
                        if i < searchcount:
                            gpsonelist.append(gpslist[i])
                        i = i + 1
                               
                    #proc = Process(target=generatecoinkey, args=(liblist[index],password,gps,nround,resultlist)) 
                    proc = Thread(target=revoverycoinkey, args=(True, liblist[index],password,gpsonelist,nround,bdebugflag,resultlist)) 
                    
                    procs.append(proc) 
                    proc.start()                   
                
                
                for proc in procs: 
                    proc.join()
                    
                progress(i, searchcount, status='Recovery Status')
                
                for strres in resultlist: 
                    if len(strres) > 0:
                        jsonobj = json.loads(strres)
                        adress = jsonobj['bitcoin address base58']
                        
                        if bdebugflag == True:
                            foutdebugfile.write(json.dumps(jsonobj) + "\n")
                        
                        tsql = (adress,)
                        dc.execute('SELECT * FROM balance WHERE address=?', tsql)
                        rows = dc.fetchall()
                        
                        if len(rows) > 0:                        
                           strbalance = str(rows[0][1])                                                      
                           jsonobj.update(balance = strbalance )
                           foutfile.write(json.dumps(jsonobj))
                           recoverylist.append(json.dumps(jsonobj))
                           
                if len(recoverylist) > 0:
                    break

            if bdebugflag == True:
                foutdebugfile.close()
            
            foutfile.close()        
            
        except IOError:
            print("Could not list file!")
            
        print("\n")
        print("-----------------")
        nmach = len(recoverylist)
        if nmach > 0:        
            print("find matching infomation!")
            for strd in recoverylist:
                print(strd)
        else:
            print("Can not find matching infomation!")            
        print("-----------------\n")

    for i in range(0, enginecount):
        dbconnectlist[i].close()
        
if __name__== "__main__":
    main()