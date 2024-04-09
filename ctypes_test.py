from aes.aes import sub_bytes, bytes2matrix, shift_rows
import unittest
import random
import ctypes

rijndael = ctypes.CDLL('./rijndael.so')


class TestEncryption(unittest.TestCase):
    def test_sub_bytes(self):
        for i in range(0,3):
            buffer = random.randbytes(16)
            block_c = bytes(buffer)
            plain_state = bytes2matrix(buffer)
            rijndael.sub_bytes(block_c)
            sub_bytes(plain_state)
            flat_list = [item for sublist in plain_state for item in sublist]
            block_python = bytes(flat_list)
            self.assertEqual(block_python, block_c)



if __name__ == '__main__':
    unittest.main()
