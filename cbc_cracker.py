#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__    = '17.10.2020'
__author__  =  'cemonatk'

from aes_lib import AES_CBC
from base64 import b64decode, b64encode
import urllib.request
import urllib.parse
from time import sleep

def return_blocks(data):
    """
    Splits data into blocks.
    :param data: data is ciphertext.
    :return: blocks python list object.
    """
    blocks = []
    for i in range(len(data) // 16):
        blocks.append(data[i * 16:(i + 1) * 16]) 
    return blocks

def get_ciphertext():
    """
    Gathers ciphertext from web page
    :return: ciphertext
    """
    ciphertext = urllib.request.urlopen(BASE_UR).read()
    return ciphertext.decode("utf-8") 

def check_padding(ciphertext):
    """
    Checks the padding if it is correct.
    :param ciphertext
    :return: True if padding is correct, False otherwise.
    """
    cipher_url = urllib.parse.quote(b64encode(ciphertext)).replace("/", "%2f")
    url = "{0}/decrypt?ciphertext={1}".format(BASE_UR, cipher_url)
    try:
        return urllib.request.urlopen(url).getcode() == 200
    except:
        return False

def find_plainblock(block_index):
    """
    Reveals plaintext of each block of the ciphertext.
    :param block_index
    :return: 'plaintext' which is the plaintext of the ciphertext[block_index].
    """
    clean_chars = []
    
    for i in range(1,17):
        for byte in range(0, 256):
            # Brute force the byte via 'check_padding'.
            temp_cipher[-i] = byte
            
            # Test if padding is correct to find the value.
            if check_padding(bytes(temp_cipher)+blocks[block_index+1]): 
                # print({0} {1}".format(str(bytes(temp_cipher).hex()), str(blocks[block_index+1].hex())))
                pointer = i

                # Padding is correct, now calculate the plaintext[-i] and store it.
                plaintext[-i] = blocks[block_index][-i] ^ byte ^ i
                
                ascii_value = plaintext[-i]
                # Almost .isalnum() in order to pretty print current plaintext.
                if 47 < ascii_value and ascii_value < 127:  
                    clean_chars.append(chr(ascii_value))
                    print("{0}. block of plaintext is:{1}".format(str(block_index+1), ''.join(clean_chars[::-1])))
                
        for j in range(1, pointer+1):
            # To decode next byte, choosing a new temp_cipher for the position which was found.
            temp_cipher[-j] = plaintext[-j] ^ blocks[block_index][-j] ^ i+1
    
    return plaintext

def crack_message(blocks):
    """
    Reveals secret message.
    :param blocks
    :return: 'secret' which is the plaintext of the ciphertext.
    """
    secret = "" 
    print("Initialization Vector:\n{0}\n".format(blocks[0].hex())) # First block is IV in our use case.
    print("Ciphertext as blocks:\n{0}\nCracking...\n".format(' | '.join([(byte.hex()) for byte in blocks if byte != blocks[0]])))
    
    # Cracking each block of the ciphertext to concate them later within the 'secret' variable.
    for block_index in range(0, len(blocks)-1):  
        plaintext = find_plainblock(block_index)
        # To get rid of padding, check if byte is greater than 16.          
        secret += ''.join([chr(byte) for byte in plaintext if byte > 16])
    return secret

if __name__ == '__main__':
    BASE_UR = "http://127.0.0.1:5000"
    blocks = return_blocks(b64decode(get_ciphertext()))
    block_size = len(blocks)
    if block_size <= 1:
        raise SystemExit("Error: block size less than or equal to 1!")
    print("Total number of blocks: {0}".format(str(block_size-1)))
    pointer = 0
    # Let's initialize byte arrays with 16 zeros in order to fill them up later on. 
    # They are holders for any future values.
    temp_cipher = bytearray([0 for _ in range(16)])
    plaintext = bytearray([0 for _ in range(16)])
    print("Secret Message: {0}".format(crack_message(blocks)))