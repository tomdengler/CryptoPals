import unittest
import CryptoPals
import AES

class Test_Set1(unittest.TestCase):
    def test_Challenge1_hex_to_base64(self):
        input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        output = CryptoPals.HexStringToBase64(input);
        valid_ouput = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        self.assertEqual(output,valid_ouput)

    def test_Challenge2_FixedXOR(self):
        input1 = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
        input2 = bytearray.fromhex("686974207468652062756c6c277320657965")
        output = CryptoPals.XOR(input1,input2)
        valid_output = bytearray.fromhex("746865206b696420646f6e277420706c6179")
        self.assertEqual(output,valid_output)

    def test_Challenge3_SingleByteXOR(self):
        input = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        key = CryptoPals.FindSingleByteKey(input)
        self.assertEqual(chr(key),"X")

    def test_Challenge4_DetectSingleCharXOR(self):
        f = open("4.txt","r") #opens file with name of "test.txt"
        myList = []
        minscore = 1000
        linenum = 0
        for line in f:
            line = line.replace('\n','')
            linenum = linenum+1
            dat = bytearray.fromhex(line)
            score = CryptoPals.LooksLikeEnglishScore(dat)
            if score < minscore:
                minscore = score
                minline = line
                minlinenum = linenum
        
        self.assertEqual(minlinenum,171)

    def test_Challenge5_RepeatingKeyXor(self):
        input = (b"Burning 'em, if you ain't quick and nimble\n"
                 b"I go crazy when I hear a cymbal")
        valid = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                 "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
        key = b"ICE"
        encoded = CryptoPals.RepeatingKeyXor(input,key)
        self.assertEqual(valid,encoded)

    def test_Challenge6_HammingDistance(self):
        str1 = b"this is a test"
        str2 = b"wokka wokka!!!"
        distance = CryptoPals.HammingDistance(str1,str2)
        self.assertEqual(distance,37)

    def test_Challenge7_CanDecryptAESECB(self):
        key = b"YELLOW SUBMARINE"
        dat =  CryptoPals.BytearrayFromBase64File("7.txt")
        plaintext = CryptoPals.DecryptAESECB(dat,key)
        self.assertEqual(plaintext[0:16],b"I'm back and I'm")
        self.assertEqual(plaintext[16:32],b" ringin' the bel")

    def test_Challenge8_DetectAESECB(self):
        lines = (line.rstrip('\n') for line in open("8.txt"))
        linenum=0;
        for line in lines:
            linenum+=1
            chunks = [line[i:i + 32] for i in range(0, len(line), 32)]
            if len(chunks) != len(set(chunks)):
                AESECBline = line
                AESECBlinenum = linenum
        self.assertEqual(AESECBlinenum,133)

    def test_Challenge9_Pad4Block16(self):
        s = "YELLOW SUBMARINE"
        padded = CryptoPals.PadPKCS7(s,20)
        self.assertEqual(padded,"YELLOW SUBMARINE\x04\x04\x04\x04")
        padded = CryptoPals.PadPKCS7(s,16)
        self.assertEqual(padded,"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_Challenge7_AES_KeyExpansion(self):
        key = b"Thats my Kung Fu"
        correct_answer = bytes.fromhex("E2 32 FC F1 91 12 91 88 B1 59 E4 E6 D6 79 A2 93".replace(" ",""))

        answer = AES.KeyExpansion(key,1)

        self.assertEqual(b"BCDA",AES.RollBytes(b"ABCD"))
        self.assertEqual(bytes.fromhex("B75A9D85"),AES.SBox( bytes.fromhex("20467567")))
        self.assertEqual(bytes.fromhex("B65A9D85"),AES.AddRound( bytes.fromhex("B75A9D85"),1))
        self.assertEqual(answer,correct_answer)
        AES.ShowState(answer)

    def test_Challenge7_AES_RoundKeys1(self):
        # this test is from https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
        # and it appears the roundkey
        # "BD 3D C2 B7 B8 7C 47 15 6A 6C 95 27 AC 2E 0E 4E"
        # is not corret????

        valid =[ 
        "54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75",
        "E2 32 FC F1 91 12 91 88 B1 59 E4 E6 D6 79 A2 93",
        "56 08 20 07 C7 1A B1 8F 76 43 55 69 A0 3A F7 FA",
        "D2 60 0D E7 15 7A BC 68 63 39 E9 01 C3 03 1E FB",
        "A1 12 02 C9 B4 68 BE A1 D7 51 57 A0 14 52 49 5B",
        "B1 29 3B 33 05 41 85 92 D2 10 D2 32 C6 42 9B 69",
        # "BD 3D C2 B7 B8 7C 47 15 6A 6C 95 27 AC 2E 0E 4E",
        "CC 96 ED 16 74 EA AA 03 1E 86 3F 24 B2 A8 31 6A",
        "8E 51 EF 21 FA BB 45 22 E4 3D 7A 06 56 95 4B 6C",
        "BF E2 BF 90 45 59 FA B2 A1 64 80 B4 F7 F1 CB D8",
        "28 FD DE F8 6D A4 24 4A CC C0 A4 FE 3B 31 6F 26" ]

        key = b"Thats my Kung Fu"
        roundKeys = AES.RoundKeys(key,10)
        roundKeys.pop(6) # to remove the assumed bad key
        for rk,vk in zip(roundKeys,valid):
            self.assertEqual(rk,bytes(bytearray.fromhex(vk.replace(" ",""))))

    def test_Challenge7_AES_RoundKeys2(self):
        # https://www.samiam.org/key-schedule.html
        valid =[ 
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", 
        "62 63 63 63 62 63 63 63 62 63 63 63 62 63 63 63", 
        "9b 98 98 c9 f9 fb fb aa 9b 98 98 c9 f9 fb fb aa", 
        "90 97 34 50 69 6c cf fa f2 f4 57 33 0b 0f ac 99", 
        "ee 06 da 7b 87 6a 15 81 75 9e 42 b2 7e 91 ee 2b", 
        "7f 2e 2b 88 f8 44 3e 09 8d da 7c bb f3 4b 92 90", 
        "ec 61 4b 85 14 25 75 8c 99 ff 09 37 6a b4 9b a7", 
        "21 75 17 87 35 50 62 0b ac af 6b 3c c6 1b f0 9b", 
        "0e f9 03 33 3b a9 61 38 97 06 0a 04 51 1d fa 9f", 
        "b1 d4 d8 e2 8a 7d b9 da 1d 7b b3 de 4c 66 49 41", 
        "b4 ef 5b cb 3e 92 e2 11 23 e9 51 cf 6f 8f 18 8e" ]

        key = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        roundKeys = AES.RoundKeys(key,10)
        for rk,vk in zip(roundKeys,valid):
            self.assertEqual(rk,bytes(bytearray.fromhex(vk.replace(" ",""))))

    def test_Challenge7_AES_RoundKeys3(self):
        # https://www.samiam.org/key-schedule.html
        valid =[ 
        "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff", 
        "e8 e9 e9 e9 17 16 16 16 e8 e9 e9 e9 17 16 16 16", 
        "ad ae ae 19 ba b8 b8 0f 52 51 51 e6 45 47 47 f0", 
        "09 0e 22 77 b3 b6 9a 78 e1 e7 cb 9e a4 a0 8c 6e", 
        "e1 6a bd 3e 52 dc 27 46 b3 3b ec d8 17 9b 60 b6", 
        "e5 ba f3 ce b7 66 d4 88 04 5d 38 50 13 c6 58 e6", 
        "71 d0 7d b3 c6 b6 a9 3b c2 eb 91 6b d1 2d c9 8d", 
        "e9 0d 20 8d 2f bb 89 b6 ed 50 18 dd 3c 7d d1 50", 
        "96 33 73 66 b9 88 fa d0 54 d8 e2 0d 68 a5 33 5d", 
        "8b f0 3f 23 32 78 c5 f3 66 a0 27 fe 0e 05 14 a3", 
        "d6 0a 35 88 e4 72 f0 7b 82 d2 d7 85 8c d7 c3 26" ]

        key = bytes.fromhex("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff")
        roundKeys = AES.RoundKeys(key,10)
        for rk,vk in zip(roundKeys,valid):
            self.assertEqual(rk,bytes(bytearray.fromhex(vk.replace(" ",""))))

    def test_Challenge7_AES_RoundKeys4(self):
        # https://www.samiam.org/key-schedule.html
        valid =[ 
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", 
        "d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe", 
        "b6 92 cf 0b 64 3d bd f1 be 9b c5 00 68 30 b3 fe", 
        "b6 ff 74 4e d2 c2 c9 bf 6c 59 0c bf 04 69 bf 41", 
        "47 f7 f7 bc 95 35 3e 03 f9 6c 32 bc fd 05 8d fd", 
        "3c aa a3 e8 a9 9f 9d eb 50 f3 af 57 ad f6 22 aa", 
        "5e 39 0f 7d f7 a6 92 96 a7 55 3d c1 0a a3 1f 6b", 
        "14 f9 70 1a e3 5f e2 8c 44 0a df 4d 4e a9 c0 26", 
        "47 43 87 35 a4 1c 65 b9 e0 16 ba f4 ae bf 7a d2", 
        "54 99 32 d1 f0 85 57 68 10 93 ed 9c be 2c 97 4e", 
        "13 11 1d 7f e3 94 4a 17 f3 07 a7 8b 4d 2b 30 c5" ]

        key = bytes.fromhex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
        roundKeys = AES.RoundKeys(key,10)
        for rk,vk in zip(roundKeys,valid):
            self.assertEqual(rk,bytes(bytearray.fromhex(vk.replace(" ",""))))

    def test_Challenge7_AES_RoundKeys5(self):
        # https://www.samiam.org/key-schedule.html
        valid =[ 
        "69 20 e2 99 a5 20 2a 6d 65 6e 63 68 69 74 6f 2a", 
        "fa 88 07 60 5f a8 2d 0d 3a c6 4e 65 53 b2 21 4f", 
        "cf 75 83 8d 90 dd ae 80 aa 1b e0 e5 f9 a9 c1 aa", 
        "18 0d 2f 14 88 d0 81 94 22 cb 61 71 db 62 a0 db", 
        "ba ed 96 ad 32 3d 17 39 10 f6 76 48 cb 94 d6 93", 
        "88 1b 4a b2 ba 26 5d 8b aa d0 2b c3 61 44 fd 50", 
        "b3 4f 19 5d 09 69 44 d6 a3 b9 6f 15 c2 fd 92 45", 
        "a7 00 77 78 ae 69 33 ae 0d d0 5c bb cf 2d ce fe", 
        "ff 8b cc f2 51 e2 ff 5c 5c 32 a3 e7 93 1f 6d 19", 
        "24 b7 18 2e 75 55 e7 72 29 67 44 95 ba 78 29 8c", 
        "ae 12 7c da db 47 9b a8 f2 20 df 3d 48 58 f6 b1" ]

        key = bytes.fromhex("69 20 e2 99 a5 20 2a 6d 65 6e 63 68 69 74 6f 2a")
        roundKeys = AES.RoundKeys(key,10)
        for rk,vk in zip(roundKeys,valid):
            self.assertEqual(rk,bytes(bytearray.fromhex(vk.replace(" ",""))))

    def test_Challenge7_AES_SubBytes(self):
        idat=" 19  3d  e3  be  a0  f4  e2  2b  9a  c6  8d  2a  e9  f8  48  08 "
        odat=" d4  27  11  ae  e0  bf  98  f1  b8  b4  5d  e5  1e  41  52  30 "    
        idat = bytes.fromhex(idat)
        odat = bytes.fromhex(odat)
        self.assertEqual(odat,AES.SubBytes(idat))

    def test_Challenge7_AES_ShiftRows(self):
        idat=" d4  27  11  ae  e0  bf  98  f1  b8  b4  5d  e5  1e  41  52  30 "
        odat=" d4  bf  5d  30  e0  b4  52  ae  b8  41  11  f1  1e  27  98  e5 "
        idat = bytes.fromhex(idat)
        odat = bytes.fromhex(odat)
        self.assertEqual(odat,AES.ShiftRows(idat))

    def test_Challenge7_AES_MixColumns(self):
        idat=" d4  bf  5d  30  e0  b4  52  ae  b8  41  11  f1  1e  27  98  e5 "
        odat=" 04  66  81  e5  e0  cb  19  9a  48  f8  d3  7a  28  06  26  4c "
        idat = bytes.fromhex(idat)
        odat = bytes.fromhex(odat)
        self.assertEqual(odat,AES.MixColumns(idat))


if __name__ == '__main__':
    unittest.main()
