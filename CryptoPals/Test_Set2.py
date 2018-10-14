import unittest
import CryptoPals
import AES

class Test_Set2(unittest.TestCase):

    def test_C9_Pad4Block16(self):
        s = b"YELLOW SUBMARINE"
        padded = AES.PadPKCS7(s,20)
        self.assertEqual(padded,b"YELLOW SUBMARINE\x04\x04\x04\x04")
        padded = AES.PadPKCS7(s,16)
        self.assertEqual(padded,b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_C10_CanDecryptAESCBC(self):
        key = b"YELLOW SUBMARINE"
        dat =  CryptoPals.BytearrayFromBase64File("10.txt")
        iv=b'\x00'*16
        valid = b"I'm back and I'm ringin' the bell \nA rockin' on "
        plaintext = AES.DecryptBlocksCBC(dat,key,iv,3)
        self.assertEqual(plaintext,valid)

    def test_C10_CanEncryptAESCBC(self):
        randkey = b'0123456789ABCDEF'
        dat = CryptoPals.BewareTheRanger()
        dat = bytes(dat,'utf8')
        iv = b'\x00'*16
        enc1 = AES.EncryptBlocksCBC(dat,randkey,iv)
        dec1 = AES.DecryptBlocksCBC(enc1,randkey,iv)
        self.assertEqual(dat,dec1)

if __name__ == '__main__':
    unittest.main()
