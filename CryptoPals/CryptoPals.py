import base64
from itertools import groupby
import numpy
import AES
import GaliousMath
import random
from enum import Enum
import pickle
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

challenge12key = b'f56f1855a2d09d0e5de5532cf5c583ca'
challenge13key = challenge12key

def HexStringToBase64(input):
    return base64.b64encode( bytearray.fromhex(input))

def RandomBytes(len):
    return bytes([random.randint(0,255) for b in range(0,len)])

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

def RemoveWhitespace(string):
    string = string.replace(' ','')
    string = string.replace(',','')
    string = string.replace('.','')
    return string

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

def VarOfDist(bytearray1):
    mylist = list(bytearray1)
    mylist.sort()
    t = groupby(mylist)
    newlist = []
    for key,group in t:
        newlist.append(len(list(group)))
    newlist.sort(reverse=True)
    var = numpy.var(newlist)
    return var

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
    return AES.XOR(key,bytearray_input)

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
    x = AES.XOR(bytearray1,bytearray2)
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

def BewareTheRanger():
    plaintext = open("BewareTheRanger.txt", "r").read()
    return plaintext    

def chunks(dat,chunksize):
    return [dat[i:i + chunksize] for i in range(0, len(dat), chunksize)]

class AESMode(Enum):
    ECB = 1
    CBC = 2

class AESInstance:
    pass

def persist(f,someAesInstance):
    pickle.dump( someAesInstance,f)

def generate(filename,count):

    # datsource = BewareTheRanger()
    datsource = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    datmiddle = bytes(datsource,'utf8')
    
    f = open(filename,'wb')

    for t in range(count):
        print(t)
        key = RandomBytes(16)
        iv = RandomBytes(16)
        datbefore = RandomBytes(random.randint(5,10))
        datafter = RandomBytes(random.randint(5,10))
        dat = datbefore+datmiddle+datafter
        mode = AESMode(random.randint(1,2))
        if (mode==AESMode.CBC):
            enc = AES.EncryptBlocksCBC(dat,key,iv)
        else:
            enc = AES.EncryptBlocksECB(dat,key)
        aes = AESInstance()
        aes.instance = t
        aes.key = key
        aes.iv = iv
        aes.mode = mode
        aes.enc = enc
        aes.lenBefore = len(datbefore)
        aes.lenAfter = len(datafter)
        persist(f,aes)

    f.close()

def AESOracle(dat):
    blocks = chunks(dat,16)
    unique = set()
    for block in blocks:
        if not block in unique:
            unique.add(block)
        else:
            return AESMode.ECB
    return AESMode.CBC

def AESOracle2(dat):
    # this oracle is not entirely accurate 
    # but is worth retaining for some of the 
    # ideas
    mode = AESMode(random.randint(1,2))

    score = LooksLikeEnglishScore(dat)

    blocks = chunks(dat,16) 
    
    scores=[]
    for col in range(16):   
        t0 = bytearray([b[col] for b in blocks])
        scores.append(VarOfDist(t0)) 
    avg = sum(scores)/16           

    if avg>0.5:
        mode=AESMode.ECB
    else:
        mode=AESMode.CBC

    return mode

def EncryptForChallenge12_CypherModule(myString,maxblocks=0,dropblocks=0):
    unk_raw = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
           "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
           "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
           "YnkK")
    unknown_string = base64.b64decode(unk_raw)
    if dropblocks!=0:
        unknown_string=unknown_string[16*dropblocks:]
        
    dat = myString+unknown_string
    if maxblocks!=0:
        dat=dat[:maxblocks*16]

    dat = AES.PadPKCS7(dat,16)

    cipher = Cipher(algorithms.AES(challenge12key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    enc = encryptor.update(dat) + encryptor.finalize()
    return enc

def AESEncryptForChallenge12_CypherModule(dat):
    cipher = Cipher(algorithms.AES(challenge12key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    enc = encryptor.update(dat) + encryptor.finalize()
    return enc

def EncryptForChallenge12(myString,maxblocks=0,dropblocks=0):
    unk_raw = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
           "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
           "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
           "YnkK")
    unknown_string = base64.b64decode(unk_raw)
    if dropblocks!=0:
        unknown_string=unknown_string[16*dropblocks:]
        
    dat = myString+unknown_string
    if maxblocks!=0:
        dat=dat[:maxblocks*16]
    enc = AES.EncryptBlocksECB(dat,challenge12key)
    return enc

def ascii_order():
    x = EnglishTextDist()
    x = sorted(x.items(), key=lambda kv: kv[1], reverse=True)
    x = [key for key,val in x]
    lower = ''.join(x)
    upper = lower.upper()
    order = lower+upper+' 0123456789:.?!"'
    # order = upper+lower+' 0123456789:.?!"'
    ord_myascii= [ord(o) for o in order]
    ord_nonascii = list(set(i for i in range(256))-set(ord_myascii))
    return ord_myascii+ord_nonascii

def Challenge12():   

    encprior = b''
    for i in range(5,50):
         datbefore=bytes('A','utf8')*i
         enc = EncryptForChallenge12_CypherModule(datbefore)
         if enc[:i-1]==encprior[:i-1]:
             blocksize = i-1
             
             print("The blocksize is : ",blocksize)
             print("{} : {}".format(i,binascii.hexlify(enc[:36])))
             break
         encprior=enc[:i]

    datbefore=bytes('A','utf8')*blocksize*2
    enc = EncryptForChallenge12_CypherModule(datbefore)
    print("AESMode:",AESOracle(enc))

    unknown_string = b''
    for block in range(0,4):
        plaintext=b''

        for p in range(0,16):
            datbefore = bytes('A','utf8')*(blocksize-(p+1)) # +plaintext
            enc = EncryptForChallenge12_CypherModule(datbefore,2,block)
            lookup = enc[:16]


            for i in ascii_order(): # range(256):
                dat = datbefore+plaintext+bytes(chr(i),'utf8')
                enc = AESEncryptForChallenge12_CypherModule(dat)
                if lookup==enc[:16]:
                    plaintextchar = bytes(chr(i),'utf8')
                    break

            print("The {} char of the unknown string is: {}".format(p,plaintextchar))
            plaintext+=plaintextchar
        unknown_string += plaintext

    return unknown_string

def Challenge11():
    filename = 'aesrec2.pickle'
    count = 100
    # generate(filename,count)

    f = open(filename,'rb')

    correctCount = 0
    for t in range(count):
        xyz = pickle.load(f)
        print(xyz.mode)
        guess = AESOracle2(xyz.enc)
        
        if guess==xyz.mode:
            correctCount+=1

    f.close()

    print("Percent correct {} of {} : {}".format(correctCount, count, 100*correctCount/count))

def kv_parser(str):
    parts = str.split("&")
    kv = dict()
    for part in parts:
        k,v = part.split("=")
        kv[k]=v
    return kv

def profile_for(email):
    email = email.replace("&","")
    email = email.replace("=","")
    profile = dict()
    profile["email"]=email
    profile["uid"]=10
    profile["role"]="user"
    return profile

def encode_profile(profile):
    return "email={}&uid={}&role={}".format(profile['email'],profile['uid'],profile['role'])

def C13_encrypted_user_input(email):
    profile = profile_for(email)
    encoded = bytes(encode_profile(profile),'utf8')
    encrypted=AES.EncryptBlocksECB(encoded,challenge13key)
    return encrypted

def C13_decode_encrypted_profile(enc):
    dec = AES.DecryptBlocksECB(enc,challenge13key)
    return dec.decode('utf8')

def Challenge13():
    # request a valid encrypted block where we know the second block will be a padded 'admin'
    admin = AES.PadPKCS7(b'admin',16)
    adminenc= C13_encrypted_user_input('AAAAAAAAAA'+admin.decode('utf8')+'abc.net')
    adminblock = adminenc[16:32]

    # substitute the adminblock at the end of a regular block
    enc = C13_encrypted_user_input('01234@abc.net')
    encadmin = enc[:-16]+adminblock
    dec = C13_decode_encrypted_profile(encadmin)                                   
    print(kv_parser(dec))

def Challenge14_GetEncrypted(my_string):
    unk_raw = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
           "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
           "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
           "YnkK")
    unknown_string = base64.b64decode(unk_raw)
    random_prefix = RandomBytes(random.randint(0,48))
    dat = random_prefix+bytes(my_string,'utf8')+unknown_string
    dat = AES.PadPKCS7(dat,16)

    cipher = Cipher(algorithms.AES(challenge12key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    enc = encryptor.update(dat) + encryptor.finalize()
    return enc


def Challenge14():
    myText = "A"*32
    enc1 = Challenge14_GetEncrypted(myText)
    
    diff = False
    while not diff:
        enc2 = Challenge14_GetEncrypted(myText)
        diff = enc1[-16:]!=enc2[-16:]
    chunks1 = chunks(enc1,16)
    chunks2 = chunks(enc2,16)

    chunks1_pos = 0
    for c in chunks1:
        if c in chunks2:
            break
        chunks1_pos+=1
    aaa_chunk = c

    # now make AAA be on a chunk boundary
    found = False
    myText = "A"*16
    while not found:
        enc = Challenge14_GetEncrypted(myText)
        found = aaa_chunk in chunks(enc,16)

    enc_chunks = chunks(enc,16)
    last_chunk = enc_chunks[-1]
    aaa_pos = enc_chunks.index(aaa_chunk)
    lookup_pos = aaa_pos+1
    lookup = enc_chunks[lookup_pos]
    lookup_from_end = lookup_pos-len(enc_chunks)

    
    unknown_string = '' 
    plaintext = '' 

    for p in range(0,16):
        for i in ascii_order():

            # get target enc bytes
            myText = "A"*(31-p)+plaintext+chr(i)
            found = False
            while not found:
                enc = Challenge14_GetEncrypted(myText)
                enc_chunks = chunks(enc,16)
                found = (aaa_chunk in enc_chunks) and (enc_chunks[-1]==last_chunk)
            aaa_pos = enc_chunks.index(aaa_chunk)
            target = enc_chunks[aaa_pos+1]

            #get enc bytes of last chunk when mytext is 1 bytes less
            found  = False
            myText = "A"*16 + "B"*(15-p)
            while not found:
                enc = Challenge14_GetEncrypted(myText)    
                enc_chunks = chunks(enc,16)
                found = aaa_chunk in enc_chunks
            last_chunk_15 = enc_chunks[-1]

            # check shortened mytext
            found = False
            myText = "A"*(15-p)
            while not found:
                enc = Challenge14_GetEncrypted(myText)    
                enc_chunks = chunks(enc,16)
                found = last_chunk_15 == enc_chunks[-1]

            if target in enc_chunks:
                plaintextchar = chr(i)
                break

        print("The {} char of the unknown string is: {}".format(p,plaintextchar))
        plaintext+=plaintextchar
        unknown_string += plaintext

    return None

def main():

    # Challenge11()
    # unknown_string = Challenge12()
    # Challenge13()
    Challenge14()
   
    print("hey")   
  
if __name__== "__main__":
    main()
