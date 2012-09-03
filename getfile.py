#!/usr/bin/env python

import os
import urllib
import binascii

from base64 import b64encode, b64decode
from M2Crypto.EVP import Cipher  
from M2Crypto import SMIME, BIO

ENC=1
DEC=0
"""

# encrypt
  cipher = EVP.Cipher(alg='aes_256_cbc', key=unhexlify(test['KEY']), iv=unhexlify(test['IV']), op=enc)
  v = cipher.update(data)
  v = v + cipher.final()
  v = b64encode(v)
  return v

# decrypt
data = b64decode(data)
cipher = EVP.Cipher(alg='aes_256_cbc', key=unhexlify(test['KEY']), iv=unhexlify(test['IV']), op=dec)
v = cipher.update(data)
v = v + cipher.final()
return v
"""

def main():
    """ The script takes as argument the content of PATH_INFO, that is to say
    the string after the script name in the query URL.
    The format is: http://<server>/<path_to_the_script>/<file_id>~<key_id>
    (note the "~" in between), where:
    file_id: file to get
    key_id: identifier of the key to encrypt the file
    """

    # SETTINGS for the key exchange server connection
    KEY_SERVER_URL = "http://localhost/cgi-bin/"
    KEY_SCRIPTNAME = "main.py/"

    # SETTINGS for the server authentication
    PRIVATE_KEY_FILENAME = "luventur_privkey.pem"
    CERT_FILENAME = "luventurx509.cer"

    print "Content-Type: text/plain\n"
    
    # Get the arguments
    query = os.environ["PATH_INFO"][1:] # remove the first "/" from PATH_INFO
    argv = query.split("~")
    file_id = argv[0]
    key_id = argv[1]

    # Get the key
    command = "get/"+key_id
    pkcs7 = urllib.urlopen(KEY_SERVER_URL + KEY_SCRIPTNAME + command).read()

    # Decript the key
    s = SMIME.SMIME() # Prepare an SMIME object
    def passphrase_fun(self):
        return "pass"
    s.load_key(PRIVATE_KEY_FILENAME, CERT_FILENAME, passphrase_fun)
    p7 = SMIME.load_pkcs7_bio(BIO.MemoryBuffer(pkcs7))
    key = s.decrypt(p7)
    
    # CHECK IF THIS IS NEEDED
    #key = binascii.unhexlify(key)
    # END CHECK

    # Get the IV from the file id
    iv = file_id[-33:-1] # Take 32 chars (128 bits) from the id, excluding the last (could be NaN)
    #iv = binascii.unhexlify(iv) # Translate to binary

    # Get the file
    clear_text = open(file_id).read() # TODO: open the real file from cvmfs

    # Encrypt
    cipher = Cipher('aes_256_cbc', key, iv, op=ENC) # TODO: ask the type of the key ('aes_256_cbc') to the server
    v = cipher.update(clear_text)
    v = v + cipher.final()
    v = b64encode(v)

    print v

    return


if __name__ == '__main__':
    main()
