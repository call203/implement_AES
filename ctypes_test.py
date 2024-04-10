import sys
sys.path.append('./aes')
from aes import bytes2matrix,sub_bytes,shift_rows
import unittest
import random
import ctypes

rijndael = ctypes.CDLL('./rijndael.so')

list2matrix = rijndael.list2matrix
list2matrix.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 
matrix2list = rijndael.matrix2list
matrix2list.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 

def compute_python_func(buffer,f):
    python_matrix = bytes2matrix(buffer)
    f(python_matrix)
    python_result = []
    [python_result.extend(row) for row in python_matrix]
    return python_result

def compute_c_func(buffer,f):
    c_matirx = list2matrix(buffer)
    f(c_matirx)
    c_list = matrix2list(c_matirx)
    c_result = (ctypes.c_ubyte * 16)()
    ctypes.memmove(c_result,c_list, 16 * ctypes.sizeof(ctypes.c_ubyte))
    return c_result
            
class TestEncryption(unittest.TestCase):
    def test_sub_bytes(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            python_result = compute_python_func(buffer,sub_bytes)
            c_result = compute_c_func(buffer,rijndael.sub_bytes)
  
            self.assertEqual(bytes(python_result), bytes(c_result))
    
    def test_shift_rows(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            python_result = compute_python_func(buffer,shift_rows)
            c_result = compute_c_func(buffer,rijndael.shift_rows)
  
            self.assertEqual(bytes(python_result), bytes(c_result))
            

                


if __name__ == '__main__':
    unittest.main()
