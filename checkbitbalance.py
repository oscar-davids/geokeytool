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

from ecdsa import SigningKey, SECP256k1

from Crypto.Cipher import AES
from clbfcrypt import clbflib

from threading import Thread
from multiprocessing import Process, Queue

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "python-bitcoinrpc"))

def find_bitcoin_cli():
    if sys.version_info[0] < 3:
        from whichcraft import which
    if sys.version_info[0] >= 3:
        from shutil import which
    return which('bitcoin-cli')

BITCOIN_CLI_PATH = str(find_bitcoin_cli())

enginecount = 5
print(enginecount)


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


def generatecoinkey(ablib, password, gps, nround, resultlist):

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
    
    print("private key            : " + privateKey)
    print("public key             : " + publicKey)
    # print("public key sha256: " + binascii.hexlify(hashed_sha256).decode("utf-8"))
    # print("public key ripemd160: " + binascii.hexlify(hashed_ripemd160).decode("utf-8"))
    # print("public key ripemd160 and version: " + binascii.hexlify(hashed_ripemd160_with_version).decode("utf-8"))
    # print("public key ripemd160 and version sha256: " + binascii.hexlify(hashed_ripemd160_with_version_sha256).decode("utf-8"))
    # print("public key ripemd160 and version sha256 round two: " + binascii.hexlify(hashed_ripemd160_with_version_roundtwo_sha256).decode("utf-8"))
    # print("public key checksum: " + binascii.hexlify(checksum).decode("utf-8"))           
    ##print("bitcoin address: " + bitcoinaddress)
    #print("bitcoin address base58 : " + bitcoinaddressbase58)            
    #print("wif: " + walletinputformat)
    
    jsonstr = "{" + '''"password":''' + '''"''' + password + '''",''' + " \n"
    jsonstr += '''"gps":''' + '''"''' + gps + '''",''' + " \n"
    jsonstr += '''"bcrypt output1":''' + '''"''' + hashed_pw + '''",''' + " \n"
    jsonstr += '''"bcrypt output2":''' + '''"''' + hashed_gps + '''",''' + " \n"
    jsonstr += '''"private key":''' + '''"''' + privateKey + '''",''' + " \n"
    jsonstr += '''"public key":'''+ '''"'''  + publicKey + '''",''' + " \n"
    jsonstr += '''"bitcoin address":'''+ '''"'''  + bitcoinaddress + '''",''' + " \n" 
    jsonstr += '''"bitcoin address base58":'''+ '''"'''  + bitcoinaddressbase58 + '''",''' + " \n"
    jsonstr += '''"wif":''' +  '''"''' + walletinputformat + '''",''' + "}"+ "\n"
    
    resultlist.append(jsonstr)
    #resultlist.put(jsonstr)
    return


def check1(addr):
	try:
		request = 'https://blockchain.info/q/addressbalance/' + addr
		response = requests.get(request, timeout=10)
		content = int(response.json())
		return content
	except KeyboardInterrupt:
		exit()
	except Exception:
		return -1

def check2(addr):
	try:
		request = 'http://btc.blockr.io/api/v1/address/info/' + addr
		response = requests.get(request, timeout=10)
		content = response.json()
		content = int(content['data'] ['balance'] * 100000000)
		return content
	except KeyboardInterrupt:
		exit()
	except Exception:
		return -1

def check3(addr):
	try:
		request = 'https://bitcoin.toshi.io/api/v0/addresses/' + addr
		response = requests.get(request, timeout=10)
		content = response.json()
		content = content['balance']
		return content
	except KeyboardInterrupt:
		exit()
	except:
		if 'response' in locals():
			if response.status_code == 404:
				return 0
			else:
				return -1
		else:
			return -1
			
def check4(addr):
	try:
		request = 'https://blockexplorer.com/api/addr/' + addr
		response = requests.get(request, timeout=10)
		content = response.json()
		content = int(content['balanceSat'])
		return content
	except KeyboardInterrupt:
		exit()
	except Exception:
		return -1
        
def check5(addr):
	try:
		request = 'https://api.blockcypher.com/v1/btc/main/addrs/' + addr + '/balance'
		response = requests.get(request, timeout=10)
		content = response.json()
		content = int(content['balance'])
		return content
	except KeyboardInterrupt:
		exit()
	except Exception:
		return -1
        
def checkcoinbalance(adress, nid, resultlist):

    if len(adress) == 0:
        return    
    
    if nid == 0:
        balance = check1(adress)
    elif nid == 1:
        balance = check2(adress)        
    elif nid == 2:
        balance = check3(adress)        
    elif nid == 3:
        balance = check4(adress)        
    elif nid == 4:
        balance = check5(adress)
    
    strbalance = "balance:"
    if balance >= 0:
        strbalance = strbalance + str(balance) + " SATOSHIS"
    else:
        strbalance = strbalance + "not checked"
    
    strlog = adress + " " + strbalance
    print(strlog)
    strlog += "\n"
    resultlist.append(strlog)
    #resultlist.put(jsonstr)
    return
    
#https://blockchain.info/address/%s?format=json" % check_address    
#https://api.blockcypher.com/v1/btc/main/addrs/ address

#https://blockchain.info/q/addressbalance/ + addr
#http://btc.blockr.io/api/v1/address/info/ + addr
#https://bitcoin.toshi.io/api/v0/addresses/' + addr
#https://blockexplorer.com/api/addr/' + addr
#https://chain.api.btc.com/v3/address/' + addr
#https://www.bitgo.com/api/v1/address/' + addr
#https://api.blocktrail.com/v1/btc/address/' + addr + '?api_key=MY_APIKEY'
#https://api.blockcypher.com/v1/btc/main/addrs/' + addr + '/balance'
#https://api.kaiko.com/v1/addresses/' + addr
#https://chainflyer.bitflyer.jp/v1/address/' + addr
#https://insight.bitpay.com/api/addr/' + addr + '/?noTxList=1'
#https://api.coinprism.com/v1/addresses/' + addr
#https://www.blockonomics.co/api/balance

def buildutxodb(dbpath):

    homepath = os.path.expanduser ('~')
    pathcoindb = homepath + "/.bitcoin/chainstate"
    
    if os.path.exists(pathcoindb) == False:
        print("There is no bitcoin database.")
        return False


    
#python checkbitbalance.py --input coinkey.txt --out balances.txt

def main():
    parser = argparse.ArgumentParser(description='Generate Geocoin key.')
    parser.add_argument('--input', type=str, help='geokeyinfo contain bitcoin address json file')
    parser.add_argument('--out', type=str, help='contain bitcoin address balance')   
    
    args = parser.parse_args()

    #password=bytes(args.password, "utf8")
    sinfile = args.input
    #gps=bytes(args.gps, "utf8")
    soutfile = args.out
    nround  = 0
    
    homepath = os.path.expanduser ('~')
    pathcoindb = homepath + "/.bitcoin/chainstate"
    
    sbalancedb = "./dbbalance.db"
    
    if os.path.isfile(sbalancedb) == False:
        print("There is no coin UTXO database.")
        print("To build a UTXO database, Please confirm bitcoin is installed.")
        print("-----Starting build UTXO database.-----")
        print("-----It takes more 30 minutes.-----")
        return
        
    
    conn = sqlite3.connect(sbalancedb)
    dc = conn.cursor()

    addressdata = []
    try:
        #finfile = open(sinfile, 'r')
        #with open(sinfile, 'r') as json_file:
        #    addressdata = json.load(json_file)
        strjson = ""
        with open(sinfile, 'r') as f:
            for n, line in enumerate(f, 1):
                strjson = strjson + line
                if n % 11 == 0: # this line is in an odd-numbered row
                    #print(strjson)
                    addressdata.append(json.loads(strjson))
                    strjson = ""
            
        addresscount = len(addressdata)
        print(addresscount)
        
        foutfile = open(soutfile, 'w')        
# for simplicity in testing the rounds are set to 32 rounds = 2^5 while the recommended production rounds are 2^16, 65536 rounds.
# this results in about 1 key every 500 ms on a state of the art nvidia but takes about 4 minutes on a single threaded cpu process.
#hashed_pw = bcrypt.kdf(password=password, salt=gps, desired_key_bytes=32, rounds=32)
#private_key = bcrypt.kdf(password=gps, salt=hashed_pw, desired_key_bytes=32, rounds=32)
#blib = clbflib()
#hash = blib.process("password", "16bytesalt", round)
        naddr = 0

        #while naddr < addresscount:
        while naddr < addresscount:        
             #cmd = "bitcoin-cli getreceivedbyaddress " +  addressdata[naddr]['bitcoin address base58']
             adress = addressdata[naddr]['bitcoin address base58']             
                          
             tsql = (adress,)
             dc.execute('SELECT * FROM balance WHERE address=?', tsql)
             rows = dc.fetchall()
             
             if len(rows) > 0:
             
                strres = adress +": " + str(rows[0][1])
             else:
                strres = adress +": " + "no balance"
             
             print(strres)
                
             naddr += 1
             strres += "\n"   
            #foutfile.write(strres)            
               
        foutfile.close()
        
    except IOError:
        print("Could not list file!")

    conn.close()
    
if __name__== "__main__":
    main()