#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__    = '17.10.2020'
__author__  =  'cemonatk'

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad # Handmade version is used instead.

class AES_CBC(object):
    def __init__(self, key=get_random_bytes(16)):
        self.key = key 
        self.iv = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    def pkcs7_pad(self, data):
        """
        Pading to a multiple of 16 by following RFC.
        https://tools.ietf.org/html/rfc2315

        :param self: self object
        :param data: data that should be unpadded.
        :return: data with removed padding bytes.
        """
        # Calculate size of the padding
        pad_length = 16 - (len(data) % 16)
        # if [XXXXXXXXXXXXOOOO] then; pad_length = 4 
        # The last bytes are related to the size of padding. How many pads you add, you need to use that number.
        data += bytes([pad_length]) * pad_length
        # if 4 then add x04 for 4 times.
        return data

    def pkcs7_unpad(self, data):
        """
        Unpadding with same methodology which is used on pkcs7_pad()
        :param self: self object
        :param data: data that should be unpadded.
        :return: data with removed padding bytes.
        """
        # The last byte declares the number of padding bytes.
        padding = data[-1]
        # Check padding length
        if padding == 0 or padding > 16:
            return 0 # Welcome Oracle! 
        for i in range(1, padding):
            if data[-i-1] != padding:
                return 0 # Welcome Oracle! 
        return data[:-padding]

    def encrypt(self, data):
        """
        Unpadding with same methodology which is used on pkcs7_pad()
        :param self: self object
        :param data: data that should be unpadded.
        :return: data with removed padding bytes.
        """
        padded_data = self.pkcs7_pad(data)
        print(padded_data)
        ciphertext_bytes = self.cipher.encrypt(padded_data)
        return self.iv + ciphertext_bytes

    def decrypt(self, data):
        """
        Unpadding with same methodology which is used on pkcs7_unpad()
        :param self: self object
        :param data: data that should be unpadded.
        :return: data with removed padding bytes.
        """
        cipher = AES.new(self.key, AES.MODE_CBC, data[:16])
        padded_data = cipher.decrypt(data[16:])
        return self.pkcs7_unpad(padded_data)