#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__    = '17.10.2020'
__author__  =  'cemonatk'

from aes_lib import AES_CBC
from flask import Flask, request, abort
from base64 import b64decode, b64encode

app = Flask(__name__)
cipher = AES_CBC()
cleartext = "do_not_use_cbcdo_not_use_cbcdo_not_use_cbc12345!"
cleartext_bytes = bytes(cleartext, 'utf8')
ciphertext = cipher.encrypt(cleartext_bytes)

@app.route('/decrypt')
def padding_oracle():
    """
    Function for decryption operation, receives GET parameter 'ciphertext'.
    :return: HTTP Status 401 if the padding is incorrect otherwise return valid message.
    """
    get_param = request.args.get('ciphertext')
    print(get_param)
    ciphertext = b64decode(get_param)
    if cipher.decrypt(ciphertext) != 0:
        return "Padding is valid."
    else:
        abort(401) 

@app.route('/')
def serve():
    return b64encode(ciphertext)

if __name__ == '__main__':
    app.run()