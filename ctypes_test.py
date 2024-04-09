
# requring install pytest
from aes.aes import sub_bytes, bytes2matrix
import unittest
import random
import ctypes

rijndael = ctypes.CDLL('./rijndael.so')


class TestEncryption(unittest.TestCase):
    def test_sub_bytes(self):
        for i in range(0,3):
            buffer = random.randbytes(16)
            block = bytes(buffer)
            plain_state = bytes2matrix(buffer)
            rijndael.sub_bytes(block)
            sub_bytes(plain_state)
            flat_integers_list = [item for sublist in plain_state for item in sublist]
            byte_seq = bytes(flat_integers_list)
            self.assertEqual(byte_seq, block)
        
    # def test_sub_bytes():

        

