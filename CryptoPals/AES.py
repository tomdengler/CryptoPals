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


def SBox(bin):
    z = [sboxaarry_np[n] for n in [nibbles(b) for b in bin]]
    return bytes(z)

def SubBytes(bin):
    return SBox(bin)

def ShiftRows(bin):
    m = np.array(bytearray(bin)).reshape(4,4)
    m[:,1]=np.roll(m[:,1], -1, axis=0)
    m[:,2]=np.roll(m[:,2], -2, axis=0)
    m[:,3]=np.roll(m[:,3], -3, axis=0)

    r = np.ndarray.tobytes(m)
    return r

def MixColumns(bin):
    m = np.array(bytearray(bin)).reshape(4,4)
    r=b''
    for i in range(4):
        r+= GaliousMath.gmix_column(bin[i*4:4+i*4]) 
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