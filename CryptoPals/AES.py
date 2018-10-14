import numpy as np
import binascii
import GaliousMath

def XOR(byteArray1, byteArray2):
    return bytes(a ^ b for a, b in zip(byteArray1,byteArray2))

def ShowState(b):
    m = np.array(bytearray(b)).reshape(4,4)
    m = np.transpose(m)
    vhex = np.vectorize(hex)
    return vhex(m)

def ShowState2(bin):
    t = " ".join([format(b,"02X") for b in bin])
    return t

def KeyExpansion(oldkey,round):
    chunks = [oldkey[i:i + 4] for i in range(0, len(oldkey), 4)]
    t = chunks[3]
    t = RollBytes(t)
    t = SBox(t)
    t = AddRound(t,1)
    w4=XOR(chunks[0],t)
    w5=XOR(chunks[1],w4)
    w6=XOR(chunks[2],w5)
    w7=XOR(chunks[3],w6)
    r = w4+w5+w6+w7
    return r

def RoundKeys(initkey,rounds):
    w = [initkey[i:i + 4] for i in range(0, len(initkey), 4)]
    r=[]
    r.append(initkey)
    rb = 1
    for round in range(1,rounds+1):
        g = w[-1]
        g = RollBytes(g)
        g = SBox(g)
        g = AddRound(g,rb)
        w.append(XOR(w[4*round-4],g))
        w.append(XOR(w[4*round-3],w[-1]))
        w.append(XOR(w[4*round-2],w[-1]))
        w.append(XOR(w[4*round-1],w[-1]))
        r.append(w[4*round]+w[4*round+1]+w[4*round+2]+w[4*round+3])
        if (rb&(1<<7)):
            rb = 27
        else:
            rb = rb << 1

    return r


def RollBytes(b):
    t = np.array(bytearray(b))
    t = np.roll(t,-1)
    r = np.ndarray.tostring(t)
    return r

def nibbles(b):
    return (b >> 4,b & 15)

sboxarray = bytearray.fromhex("637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
    #s2 = bytearray(bytes.fromhex(s))

sboxaarry_np = np.array(sboxarray).reshape(16,16)

invsboxarray = bytearray.fromhex(
    "52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb"
    "7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb"
    "54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e"
    "08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25"
    "72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92"
    "6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84"
    "90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06"
    "d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b"
    "3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73"
    "96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e"
    "47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b"
    "fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4"
    "1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f"
    "60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef"
    "a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61"
    "17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d")

invsboxaarry_np = np.array(invsboxarray).reshape(16,16)


def SBox(bin):
    z = [sboxaarry_np[n] for n in [nibbles(b) for b in bin]]
    return bytes(z)

def SubBytes(bin):
    return SBox(bin)

def InvSubBytes(bin):
    z = [invsboxaarry_np[n] for n in [nibbles(b) for b in bin]]
    return bytes(z)

def ShiftRows(bin):
    m = np.array(bytearray(bin)).reshape(4,4)
    m[:,1]=np.roll(m[:,1], -1, axis=0)
    m[:,2]=np.roll(m[:,2], -2, axis=0)
    m[:,3]=np.roll(m[:,3], -3, axis=0)

    r = np.ndarray.tobytes(m)
    return r

def InvShiftRows(bin):
    m = np.array(bytearray(bin)).reshape(4,4)
    m[:,1]=np.roll(m[:,1], 1, axis=0)
    m[:,2]=np.roll(m[:,2], 2, axis=0)
    m[:,3]=np.roll(m[:,3], 3, axis=0)

    r = np.ndarray.tobytes(m)
    return r

def MixColumns(bin):
    m = np.array(bytearray(bin)).reshape(4,4)
    r=b''
    for i in range(4):
        r+= GaliousMath.gmix_column(bin[i*4:4+i*4]) 
    return r

def InvMixColumns(bin):
    m = np.array(bytearray(bin)).reshape(4,4)
    r=b''
    for i in range(4):
        r+= GaliousMath.inv_gmix_column(bin[i*4:4+i*4]) 
    return r

def AddRound(bin,round):
    r = bytearray(bin)
    r[0] = r[0] ^ round
    return bytes(r)

def EncryptBlockECB(block,key):
    roundkeys = RoundKeys(key,10)
    state = XOR(block,roundkeys[0])
    for round in range(1,11):
        state = SubBytes(state)        
        state = ShiftRows(state)
        if round!=10:
            state = MixColumns(state)
        state = XOR(state,roundkeys[round])
    return state

def RoundKeysForDecryptECB(key):
    roundkeys = RoundKeys(key,10)
    for round in range(1,10):
       roundkeys[round] = InvMixColumns(roundkeys[round])
    return roundkeys

def RoundKeysForEncryptECB(key):
    roundkeys = RoundKeys(key,10)
    return roundkeys

def DecryptBlockECB(block,key,roundkeys=None):
    if (roundkeys==None):
        roundkeys = RoundKeysForDecryptECB(key)
    state = XOR(block,roundkeys[10])
    for round in range(10,0,-1):
        state = InvSubBytes(state)        
        state = InvShiftRows(state)
        if round!=1:
            state = InvMixColumns(state)
        state = XOR(state,roundkeys[round-1])
    return state

def DecryptBlocksCBC(dat,key,iv,maxblocks=0):
    retPlaintext = b''
    blocks=[dat[i:i + 16] for i in range(0, len(dat), 16)]
    dropPadding = maxblocks==0
    if dropPadding:
        maxblocks=len(blocks)
    roundkeys=RoundKeysForDecryptECB(key)
    for block in blocks[0:maxblocks]:
        pblock = block
        plaintext = DecryptBlockECB(block,key,roundkeys)
        plaintext = XOR(iv,plaintext)
        retPlaintext+=plaintext
        iv=pblock
    if dropPadding:
        dropbytes=ord(plaintext[-1:])
        retPlaintext= retPlaintext[:-dropbytes]
    return retPlaintext

def PadPKCS7(bin,blocksize):
    remainder = blocksize-(len(bin) % blocksize)
    pad=bytes(chr(remainder),'utf8')
    return bin+pad*remainder

def EncryptBlocksCBC(str,key,iv,maxblocks=0):
    retBytes = b''
    dat = PadPKCS7(str,16)
    blocks=[dat[i:i + 16] for i in range(0, len(dat), 16)]
    if maxblocks==0:
        maxblocks=len(blocks)
    roundkeys=RoundKeysForDecryptECB(key)
    for block in blocks[0:maxblocks]:
        xblock = XOR(block,iv)
        enc = EncryptBlockECB(xblock,key)
        retBytes+=enc
        iv=enc
    return retBytes

def EncryptBlocksECB(str,key,maxblocks=0):
    retBytes = b''
    dat = PadPKCS7(str,16)
    blocks=[dat[i:i + 16] for i in range(0, len(dat), 16)]
    if maxblocks==0:
        maxblocks=len(blocks)
    roundkeys=RoundKeysForEncryptECB(key)
    for block in blocks[0:maxblocks]:
        enc = EncryptBlockECB(block,key)
        retBytes+=enc
    return retBytes

def DecryptBlocksECB(dat,key,maxblocks=0):
    retPlaintext = b''
    blocks=[dat[i:i + 16] for i in range(0, len(dat), 16)]
    dropPadding = maxblocks==0
    if dropPadding:
        maxblocks=len(blocks)
    roundkeys=RoundKeysForDecryptECB(key)
    for block in blocks[0:maxblocks]:
        plaintext = DecryptBlockECB(block,key,roundkeys)
        retPlaintext+=plaintext
    if dropPadding:
        dropbytes=ord(plaintext[-1:])
        retPlaintext= retPlaintext[:-dropbytes]
    return retPlaintext

