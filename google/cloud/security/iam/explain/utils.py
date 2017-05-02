
import os
import binascii

def generateModelHandle():
    return binascii.hexlify(os.urandom(16))