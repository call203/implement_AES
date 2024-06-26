import sys
sys.path.append('./aes')
from aes import bytes2matrix,sub_bytes,shift_rows,mix_columns,add_round_key,inv_sub_bytes,inv_shift_rows,inv_mix_columns
from aes import AES
import unittest
import random
import ctypes

rijndael = ctypes.CDLL('./rijndael.so')

list2matrix = rijndael.list2matrix
list2matrix.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 
matrix2list = rijndael.matrix2list
matrix2list.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 
c_encrypt_block = rijndael.aes_encrypt_block
c_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 
c_decrypt_block = rijndael.aes_decrypt_block
c_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16) 

# if key parameter has a value, it is `add_round_key` test
def compute_python_func(buffer,f,key=[]):
    python_matrix = bytes2matrix(buffer)
    if len(key) > 0:
        key_matrix = bytes2matrix(key)
        f(python_matrix,key_matrix)
    else:
        f(python_matrix)
    python_result = []
    [python_result.extend(row) for row in python_matrix] #make 1-D array accoring to c return type
    return python_result

def compute_c_func(buffer,f,key=[]):
    c_matirx = list2matrix(buffer)
    if len(key)>0:
        f(c_matirx,key)
    else:    
        f(c_matirx)
    c_list = matrix2list(c_matirx)
    c_result = (ctypes.c_ubyte * 16)() #list to ctypes array
    ctypes.memmove(c_result,c_list, 16 * ctypes.sizeof(ctypes.c_ubyte))
    return c_result
            


class TestEncryption(unittest.TestCase):
    # encryption functions
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

    # decryption functions
    def test_invert_sub_bytes(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            python_result = compute_python_func(buffer,inv_sub_bytes)
            c_result = compute_c_func(buffer,rijndael.invert_sub_bytes)

            self.assertEqual(bytes(python_result), bytes(c_result)) 

    def test_invert_shift_rows(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            python_result = compute_python_func(buffer,inv_shift_rows)
            c_result = compute_c_func(buffer,rijndael.invert_shift_rows)

            self.assertEqual(bytes(python_result), bytes(c_result))        

    def test_invert_mix_columns(self):
        for _ in range(0,3):
            buffer = random.randbytes(16)
            python_result = compute_python_func(buffer,inv_mix_columns)
            c_result = compute_c_func(buffer,rijndael.invert_mix_columns)

            self.assertEqual(bytes(python_result), bytes(c_result))    
            
    def test_expanded_key(self):
        for _ in range(0,3):
            #Python
            buffer = random.randbytes(16)
            aes = AES(buffer)
            python_result = []
            [python_result.extend(row) for row in aes._key_matrices]

            #C
            c_list = (ctypes.c_ubyte * 176)()
            rijndael.expand_key(buffer,c_list)
    
            c_result = []
            temp = []
            #python `_expand_key` returns byte([4 items]) after index 16 
            #therefore, convert result format of c function accdoring to that
            for idx,item in enumerate(c_list):
                temp.append(item)
                if((idx+1)%4 ==0):
                    if(idx > 16):
                        temp = bytes(temp)    
                    c_result.append(temp) 
                    temp = []

            self.assertEqual(c_result,python_result)

    def encrypt_block(self, plain_text, master_key, c_master_key):
        #C
        c_encryption = (ctypes.c_ubyte * 16)()
        c_encryption_array = c_encrypt_block(plain_text,bytes(c_master_key))
        ctypes.memmove(c_encryption,c_encryption_array, 16 * ctypes.sizeof(ctypes.c_ubyte))
        c_encryption = bytes(c_encryption) # ctypes_array to byte

        #Python
        aes = AES(master_key)
        python_encryption = aes.encrypt_block(plain_text)

        return c_encryption, python_encryption
    
    def decrypt_block(self, encryption_text, master_key, c_master_key):
        #C
        c_decryption = (ctypes.c_ubyte * 16)()
        
        c_decryption_array = c_decrypt_block(encryption_text,bytes(c_master_key))
        ctypes.memmove(c_decryption, c_decryption_array, 16 * ctypes.sizeof(ctypes.c_ubyte))
        c_decryption = bytes(c_decryption) 

        #Python
        aes = AES(master_key)
        python_decryption = aes.decrypt_block(encryption_text)

        return c_decryption, python_decryption

    def test_aes(self):
         for _ in range(0,3):
            plain_text = random.randbytes(16)
            master_key = random.randbytes(16)
            
            #C - key expansion
            c_master_key = (ctypes.c_ubyte * 176)()            
            rijndael.expand_key(master_key, c_master_key)
            c_master_key = bytearray(c_master_key)
            
            c_encryption, python_encryption = self.encrypt_block(plain_text, master_key, c_master_key)
            #compare cipher_text
            self.assertEqual(c_encryption,python_encryption)

            #compare recover_text
            if(c_encryption == python_encryption):
                c_decryption, python_decryption = self.decrypt_block(c_encryption, master_key, c_master_key)
                self.assertEqual(c_decryption, python_decryption)
            else:
                print("!!!! encrpytion key does not match !!!!")

            # C - compare plain_text and recover_texts
            self.assertEqual(plain_text, c_decryption)  
            # Python - compare plain_text and recover_texts
            self.assertEqual(plain_text, python_decryption)   



                





            
if __name__ == '__main__':
    unittest.main()
