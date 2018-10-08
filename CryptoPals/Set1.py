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



                

if __name__ == '__main__':
    unittest.main()
