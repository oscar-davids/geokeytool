import os
import tempfile
import argparse
import sqlite3

from hashlib import sha256
from re import match
import plyvel
from binascii import hexlify, unhexlify
from base58 import b58encode
import sys

sbalancedb = "dbbalance.db"
print(sbalancedb)

#referred following url
#https://github.com/bitcoin/bitcoin/
#https://bitcoin.org/en/full-node#linux-instructions

def ReadVarInt(data):
    n = 0
    i = 0
    while True:
        d = int(data[2 * i:2 * i + 2], 16)
        n = n << 7 | d & 0x7F
        if d & 0x80:
            n += 1
            i += 1
        else:
            return n
            
            
def DecompressAmount(x):
    
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x /= 10
    if e < 9:
        d = (x % 9) + 1
        x /= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


def Parse128Bit(utdata, offset=0):
    
    data = utdata[offset:offset+2]
    offset += 2
    more_bytes = int(data, 16) & 0x80  
    
    while more_bytes:
        data += utdata[offset:offset+2]
        more_bytes = int(utdata[offset:offset+2], 16) & 0x80
        offset += 2

    return data, offset


def TransactionUnknown(unknownkey, value):

    l_value = len(value)
    l_obf = len(unknownkey)
    
    # value to be de-obfuscated.
    if l_obf < l_value:
        extended_key = (unknownkey * ((l_value / l_obf) + 1))[:l_value]
    else:
        extended_key = unknownkey[:l_value]

    r = format(int(value, 16) ^ int(extended_key, 16), 'x')
    
    # when the formatting.
    if len(r) is l_value-1:
        r = r.zfill(l_value)

    assert len(value) == len(r)

    return r


def ModifyEndian(x):

    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = x.decode('hex')
    z = y[::-1]
    return z.encode('hex')


def ChangeHash160toBitAddress(h160, v):
    
    if match('^[0-9a-fA-F]*$', h160):
        h160 = unhexlify(h160)

    # calculated RIPEMD-160 hash.
    vh160 = chr(v) + h160
    # Double sha256.
    h = sha256(sha256(vh160).digest()).digest()    
    addr = vh160 + h[0:4]
    # Obtain the Bitcoin address by Base58 encoding
    addr = b58encode(addr)

    return addr


def DecodeData(rawdata, outpoint, version=0.15):
    

    if 0.08 <= version < 0.15:
        return DecodeV014(rawdata)
    elif version < 0.08:
        raise Exception("The utdata decoder only works for version 0.08 onwards.")
    else:        
        assert outpoint[:2] == '43'
        #
        assert len(outpoint) >= 68
        
        tx_id = outpoint[2:66]
        
        tx_index = ReadVarInt(outpoint[66:])

        code, offset = Parse128Bit(rawdata)
        code = ReadVarInt(code)
        height = code >> 1
        coinbase = code & 0x01

        data, offset = Parse128Bit(rawdata, offset)
        amount = DecompressAmount(ReadVarInt(data))

        # Finally, we can obtain the data type from 128 bit data
        out_type, offset = Parse128Bit(rawdata, offset)
        out_type = ReadVarInt(out_type)

        if out_type in [0, 1]:
            data_size = 40  # 20 bytes
        elif out_type in [2, 3, 4, 5]:
            data_size = 66  # 33 bytes (1 byte for the type + 32 bytes of data)
            offset -= 2        
        else:
            data_size = (out_type - 6) * 2  
        
        script = rawdata[offset:]
        
        assert len(script) == data_size
        
        # previous decoder
        out = [{'amount': amount, 'out_type': out_type, 'data': script}]

    return {'tx_id': tx_id, 'index': tx_index, 'coinbase': coinbase, 'outs': out, 'height': height}


def DecodeV014(utdata):
    

    # Version check
    version, offset = Parse128Bit(utdata)
    version = ReadVarInt(version)

    code, offset = Parse128Bit(utdata, offset)
    code = ReadVarInt(code)
    coinbase = code & 0x01

    vout = [(code | 0x01) & 0x02, (code | 0x01) & 0x04]

    if not vout[0] and not vout[1]:
        n = (code >> 3) + 1
        vout = []
    else:
        n = code >> 3
        vout = [i for i in xrange(len(vout)) if vout[i] is not 0]
    
    if n > 0:
        bitvector = ""
        while n:
            data = utdata[offset:offset+2]
            if data != "00":
                n -= 1
            bitvector += data
            offset += 2

        bin_data = format(int(ModifyEndian(bitvector), 16), '0'+str(n*8)+'b')[::-1]

        extended_vout = [i+2 for i in xrange(len(bin_data))
                         if bin_data.find('1', i) == i]  # Finds the index of '1's and adds 2.

        vout += extended_vout

    outs = []
    for i in vout:
    
        data, offset = Parse128Bit(utdata, offset)
        amount = DecompressAmount(ReadVarInt(data))
        # The output type is also parsed.
        out_type, offset = Parse128Bit(utdata, offset)
        out_type = ReadVarInt(out_type)
        
        if out_type in [0, 1]:
            data_size = 40  # 20 bytes
        elif out_type in [2, 3, 4, 5]:
            data_size = 66  # 33 bytes (1 byte for the type + 32 bytes of data)
            offset -= 2        
        else:
            data_size = (out_type - NSPECIALSCRIPTS) * 2  # If the data is not compacted, the out_type corresponds            

        data, offset = utdata[offset:offset+data_size], offset + data_size
        outs.append({'index': i, 'amount': amount, 'out_type': out_type, 'data': data})

    height, offset = Parse128Bit(utdata, offset)
    height = ReadVarInt(height)

    assert len(utdata) == offset

    return {'version': version, 'coinbase': coinbase, 'outs': outs, 'height': height}


def ParsingLDB(coindbpath, version=0.15, types=(0, 1)):
    counter = 0
    if 0.08 <= version < 0.15:
        prefix = b'c'
    elif version < 0.08:
        raise Exception("The utdata decoder only works for version 0.08 onwards.")
    else:
        prefix = b'C'

    # Open the LevelDB
    db = plyvel.DB(coindbpath, compression=None) 

    # Load obfuscation key (if it exists)
    o_key = db.get((unhexlify("0e00") + "obfuscate_key"))

    if o_key is not None:
        o_key = hexlify(o_key)[2:]

    not_decoded = [0, 0]
    for key, o_value in db.iterator(prefix=prefix):
        key = hexlify(key)
        if o_key is not None:
            value = TransactionUnknown(o_key, hexlify(o_value))
        else:
            value = hexlify(o_value)
  
        if version < 0.15:
            value = DecodeV014(value)
        else:
            value = DecodeData(value, key, version)

        for out in value['outs']:
            # 0 --> P2PKH
            # 1 --> P2SH
            # 2 - 3 --> P2PK
            # 4 - 5 --> P2PK

            if counter % 100 == 0:
                sys.stdout.write('\r processing : %d' % counter)
                sys.stdout.flush()
            counter += 1

            if out['out_type'] == 0:
                if out['out_type'] not in types:
                    continue
                add = ChangeHash160toBitAddress(out['data'], 0)
                yield add, out['amount'], value['height']
            elif out['out_type'] == 1:
                if out['out_type'] not in types:
                    continue
                add = ChangeHash160toBitAddress(out['data'], 5)
                yield add, out['amount'], value['height']
            elif out['out_type'] in (2, 3, 4, 5):
                if out['out_type'] not in types:
                    continue
                add = 'P2PK'
                yield add, out['amount'], value['height']
            else:
                not_decoded[0] += 1
                not_decoded[1] += out['amount']

    #print('\nunable to decode %d' % not_decoded[0])
    print('\ntotaling %d satoshi' % not_decoded[1])

    db.close()

#
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Update UTXO database from bitcoin LevelDB')
    parser.add_argument('coindbpath', metavar='PATH_TO_CHAINSTATE_DIR',type=str, help='path to bitcoin chainstate directory')
    parser.add_argument('--bitcoinversion',type=float,default=0.15, help='versions of bitcoin node')
    
    args = parser.parse_args()
    
    print('reading bitcoin bitcoin database')
    
    print(args.coindbpath)
    
    # P2PKH and P2SH mode
    keep_types = set()
    keep_types.add(0)    
    keep_types.add(1)    
    
    dbfile = sbalancedb
 
    print('making bitcoin balance database\n' + dbfile)
    
    with sqlite3.connect(dbfile) as conn:
        curr = conn.cursor()
        curr.execute(
            """
            DROP TABLE IF EXISTS balance
            """
        )

        curr.execute(
            """
            CREATE TABLE balance (
                    address TEXT PRIMARY KEY,
                    amount BIGINT NOT NULL,
                    height BIGINT NOT NULL
            )
            """
        )

        curr.execute('BEGIN TRANSACTION')

        expinsert = """
            INSERT OR IGNORE INTO balance (address, amount, height) VALUES (?, ?, ?)"""
        expupdate = """
            UPDATE balance SET
            amount = amount + ?,
            height = ?
            WHERE address = ?
            """
        for add, val, height in ParsingLDB(
                coindbpath = args.coindbpath,
                version = args.bitcoinversion,
                types = keep_types):
            curr.execute(expinsert, (add, 0, 0))
            curr.execute(expupdate, (val, height, add)) 

        conn.commit()
        curr.close()
    
    
    print('success update dbblance')
   
