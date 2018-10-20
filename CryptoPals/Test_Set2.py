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

    def test_c15_validate_padding(self):
        t = AES.RemovePKCS7(b"ICE ICE BABY\x04\x04\x04\x04")
        self.assertEqual(t,b"ICE ICE BABY")
        bad = b"ICE ICE BABY\x05\x05\x05\x05"
        with self.assertRaises(AES.PKCS7Error):
            t = AES.RemovePKCS7(bad)

if __name__ == '__main__':
    unittest.main()
