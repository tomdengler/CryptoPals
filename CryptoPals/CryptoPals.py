import base64
from itertools import groupby
import numpy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import AES

def HexStringToBase64(input):
    return base64.b64encode( bytearray.fromhex(input))

def XOR(byteArray1, byteArray2):
    return bytes(a ^ b for a, b in zip(byteArray1,byteArray2))

def FindSingleByteKey(bytearray1):
    low = 1000
    retval = None
    for b in range(256):
        test = bytes(a ^ b for a in bytearray1)
        score = EnglishTextChiScore(test)
        if score < low:
            low = score
            retval = b

    return retval

def EnglishTextDist():
    return {
        'a':	0.08167,	
        'b':	0.01492,	
        'c':	0.02782,	
        'd':	0.04253,	
        'e':	0.12702,	
        'f':	0.02228,	
        'g':	0.02015,	
        'h':	0.06094,	
        'i':	0.06966,	
        'j':	0.00153,	
        'k':	0.00772,	
        'l':	0.04025,	
        'm':	0.02406,	
        'n':	0.06749,	
        'o':	0.07507,	
        'p':	0.01929,	
        'q':	0.00095,	
        'r':	0.05987,	
        's':	0.06327,	
        't':	0.09056,	
        'u':	0.02758,	
        'v':	0.00978,	
        'w':	0.02360,	
        'x':	0.00150,	
        'y':	0.01974,	
        'z':	0.00074
         }

def EnglishTextChiScore(string):
    lc_input = string.lower()
    lc_input = lc_input.replace(b' ',b'')
    lc_input = lc_input.replace(b',',b'')
    lc_input = lc_input.replace(b'.',b'')
    r = 0
    dist = EnglishTextDist()
    for a in lc_input:
        if chr(a) in dist:
            expected = len(lc_input)*dist[chr(a)]
            r = r+((lc_input.count(a) - expected)**2)/expected
        else:
            #  print(a)
            r = r+lc_input.count(a)**2
    return r/len(lc_input)

def EnglishTextScore(string):
    lc_input = string.lower()
    lc_input = lc_input.replace(' ','')
    lc_input = lc_input.replace(',','')
    lc_input = lc_input.replace('.','')
    r = 0
    dist = EnglishTextDist()
    for a in lc_input:
        if a in dist:
            r = r+dist[a]
        else:
            print(a)
    return r/len(lc_input)

def LooksLikeEnglishScore(bytearray1):
    mylist = list(bytearray1)
    mylist.sort()
    t = groupby(mylist)
    newlist = []
    for key,group in t:
        newlist.append(len(list(group)))
    newlist.sort(reverse=True)
    total = sum(newlist)
    englishDist = list(EnglishTextDist().values())
    englishDist.sort(reverse=True)
    score = 0
    for x,y in zip(newlist,englishDist):
        score = score+(((x/total)-y)**2)/y
    return score

def repeat_to_length(s, wanted):
    a, b = divmod(wanted, len(s))
    return s * a + s[:b]

def RepeatingKeyXor(bytearray_input,bytearray_key):
    key = repeat_to_length(bytearray_key,len(bytearray_input))
    return XOR(key,bytearray_input)

def bitcount(somebyte):
    count = 0
    z = somebyte
    while z:
        if z & 1:
           count+=1
        z >>= 1
    return count

def HammingDistance(bytearray1,bytearray2):
    """Calculate the Hamming distance between two byte arrays strings"""
    assert len(bytearray1) == len(bytearray2)
    x = XOR(bytearray1,bytearray2)
    count = 0
    for abyte in x:
        count += bitcount(abyte)
    return count

def BytearrayFromBase64File(filename):
    data = open(filename, "r").read()
    decoded = base64.b64decode(data)
    return decoded

def AverageHammingDistance(bytearray1, keysize):
    total = 0
    count = 0

    x1 = bytearray1[0:keysize]
    x2 = bytearray1[1*keysize:1*keysize+keysize]
    x3 = bytearray1[2*keysize:2*keysize+keysize]
    x4 = bytearray1[3*keysize:3*keysize+keysize]
    x5 = bytearray1[4*keysize:4*keysize+keysize]

    total += HammingDistance(x1,x2)
    total += HammingDistance(x1,x3)
    total += HammingDistance(x1,x4)
    total += HammingDistance(x1,x5)
    total += HammingDistance(x2,x3)
    total += HammingDistance(x2,x4)
    total += HammingDistance(x2,x5)
    total += HammingDistance(x3,x4)
    total += HammingDistance(x3,x5)
    total += HammingDistance(x4,x5)
    count+=10

    x6 = bytearray1[5*keysize:5*keysize+keysize]
    total += HammingDistance(x1,x6)
    total += HammingDistance(x2,x6)
    total += HammingDistance(x3,x6)
    total += HammingDistance(x4,x6)
    total += HammingDistance(x5,x6)
    count+=5

    return (total/count)/keysize

def ProbableKeyLength(repeatingXORdat):
    hammingTable = []
    minkeysize = 2
    for keysize in range(minkeysize,40):
        ahd = AverageHammingDistance(repeatingXORdat,keysize)
        hammingTable.append(ahd)

    #probablyKey = min(hammingTable, key=hammingTable.get)
    sort_index = numpy.argsort(hammingTable)
    for i in range(10):
        print(minkeysize+sort_index[i],hammingTable[sort_index[i]])

    probablyKeyLength = minkeysize+sort_index[0]
    return probablyKeyLength

def FindRepeatingXORKey(dat,keylen):
    actualKey = []
    for k in range(keylen):
        chunk = list(dat[i] for i in range(k, len(dat)-k, keylen))
        key = FindSingleByteKey(chunk)
        actualKey.append(key)
    return actualKey

def DecryptAESECB(dat,key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(dat) + decryptor.finalize()
    return plaintext

def PadPKCS7(str,blocksize):
    remainder = blocksize-(len(str) % blocksize)
    return str+chr(remainder)*remainder
    

def main():
    key = b"Thats my Kung Fu"
    correct_answer = bytes.fromhex("E2 32 FC F1 91 12 91 88 B1 59 E4 E6 D6 79 A2 93".replace(" ",""))
    answer = AES.KeyExpansion(key,round)
    print(AES.ShowState2(answer))
    roundkeys = AES.RoundKeys(key,10)
    for rk in roundkeys:
        print(AES.ShowState2(rk))
    print("hey")   
  
if __name__== "__main__":
    main()
