import sys
sys.path.append('./aes')
from aes import bytes2matrix,sub_bytes,shift_rows,mix_columns,add_round_key
import unittest
import random
import ctypes

rijndael = ctypes.CDLL('./rijndael.so')

list2matrix = rijndael.list2matrix
list2matrix.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 
matrix2list = rijndael.matrix2list
matrix2list.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 

# if key parameter has a value, it is `add_round_key` test
def compute_python_func(buffer,f,key=[]):
    python_matrix = bytes2matrix(buffer)
    if len(key) > 0:
        key_matrix = bytes2matrix(key)
        f(python_matrix,key_matrix)
    else:
        f(python_matrix)
    python_result = []
    [python_result.extend(row) for row in python_matrix]
    return python_result

def compute_c_func(buffer,f,key=[]):
    c_matirx = list2matrix(buffer)
    if len(key)>0:
        f(c_matirx,key)
    else:    
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


    def test_mix_columns(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            python_result = compute_python_func(buffer,mix_columns)
            c_result = compute_c_func(buffer,rijndael.mix_columns)
  
            self.assertEqual(bytes(python_result), bytes(c_result))
            
    def test_add_round_key(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            key = random.randbytes(16)
            python_result = compute_python_func(buffer,add_round_key,key)
            c_result = compute_c_func(buffer,rijndael.add_round_key,key)
  
            self.assertEqual(bytes(python_result), bytes(c_result))
            
                
            

            

if __name__ == '__main__':
    unittest.main()
