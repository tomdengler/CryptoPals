import unittest
import CryptoPals
import AES

class Test_Set2(unittest.TestCase):

    def test_C9_Pad4Block16(self):
        s = "YELLOW SUBMARINE"
        padded = CryptoPals.PadPKCS7(s,20)
        self.assertEqual(padded,"YELLOW SUBMARINE\x04\x04\x04\x04")
        padded = CryptoPals.PadPKCS7(s,16)
        self.assertEqual(padded,"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_C10_AESCBC(self):
        key = b"YELLOW SUBMARINE"
        dat =  CryptoPals.BytearrayFromBase64File("10.txt")
        iv=iv=b'\x00'*16
        valid = b"I'm back and I'm ringin' the bell \nA rockin' on "
        plaintext = AES.DecryptBlocksCBC(dat,key,iv,3)
        self.assertEqual(plaintext,valid)

if __name__ == '__main__':
    unittest.main()
