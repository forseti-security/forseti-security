
import os
import base64

def generateModelHandle():
    return base64.b64encode(os.urandom(16))