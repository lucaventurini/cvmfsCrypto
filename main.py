#!/usr/bin/env python

import sys
import redis
import hashlib
import os
import cgi
import binascii
from M2Crypto import X509, SMIME, BIO, Rand

class Commands:
    """List of user commands"""
    OK_MSG = "200 OK"
    KO_MSG = "KO"

    def get(self, sha1code):
        """ Get key whose sha-1 is "sha1code", if exists """

        key = rediserver.hget("sha1:"+sha1code, "key")
        print key
        return

    def addk(self, gid):
        """ Create a new random key for group "gid", and 
        store it encrypted by public key of users in the group,
        as PKCS7 file """

        if self.__addk(gid): print self.OK_MSG
        else: print self.KO_MSG
        return

    def __addk(self, gid):

        # Prepare an SMIME object
        s = SMIME.SMIME()
        s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

        # Load all certificates from users in the group
        cert_stack = X509.X509_Stack() 
        users = rediserver.smembers("users_gid:"+gid)
        if users:
            for uid in users:
                x509_string = rediserver.hget("x509_uid:"+uid, "x509")
                x509 = X509.load_cert_string(x509_string)
                if x509: cert_stack.push(x509)
            s.set_x509_stack(cert_stack)

            # Encrypt
            # The new key is generated using secure random generator provided by OpenSSL
            random_string = Rand.rand_bytes(32) # TODO: change the length of the key to support other block sizes
            
            # CHECK IF THIS IS REALLY NEEDED
            # print random_string
            random_string = binascii.hexlify(random_string)
            # print random_string
            # END CHECK

            key = BIO.MemoryBuffer(random_string)
            crypted_key = s.encrypt(key)

            # Convert the key from BIO to string
            # crypted_key.write(BIO.File(sys.stdout)) # Print to standard output
            bio = BIO.MemoryBuffer()
            crypted_key.write(bio)
            pkcs7string = bio.read()

            # Store the key in redis
            sha1 = hashlib.sha1(random_string).hexdigest()
            rediserver.sadd("keys_gid:"+gid, sha1)
            rediserver.set("first_key_gid:"+gid, sha1)
            rediserver.hmset("sha1:"+sha1, {"gid" : gid, "key_type" : "aes_256_cbc", "key" : pkcs7string})
            # key_type is fixed to aes_256_cbc, for now        
            return 1
 
        return 0
    
    def remk(self, sha1code):
        """ Remove the key whose sha-1 is "sha1code" """

        if rediserver.exists("sha1:"+sha1code):
            gid = rediserver.hget("sha1:"+sha1code, "gid")

            # Remove the key from the group's list
            rediserver.srem("keys_gid:"+gid, sha1code)

            # Remove the key for good
            rediserver.delete("sha1:"+sha1code)
            print self.OK_MSG
        print self.KO_MSG+": not existing key"
        return
    
    def addu(self, x509_filename):
        """ Add an user passing its x509 certificate """

	# Let assume x509 certificate is in a local file, for now
        x509 = X509.load_cert(x509_filename)
        uid = x509.get_subject()
        # TODO: verify certificate

        if rediserver.sadd("uids", uid.as_text()):
            x509_fp = open(x509_filename)
            rediserver.hmset("x509_uid:"+uid.as_text(), {"x509" : x509_fp.read()})
            x509_fp.close()
            print self.OK_MSG
        return

    def remu(self, uid):
        """ Remove an user by name """

        # TODO: remove user from her groups
        # NB: since the user's x509 is deleted, the keys are no more encrypted with her certificate,
        # therefore, even if she is listed in the groups, she can no more decrypt new keys.
        rediserver.srem("uids", uid)
        rediserver.delete("x509_uid:"+uid)
        print self.OK_MSG
        return
		
    def join(self, uid, gid):
        """Let user "uid" join group "gid" """

        #TODO: the API for http GET requests doen't work with blank spaces. Fix.

        if rediserver.sismember("gids", gid) and rediserver.sismember("uids", uid):
            if rediserver.sadd("users_gid:"+gid, uid) \
            and self.__addk(gid): 
                print self.OK_MSG
            else:
                print self.KO_MSG
        return
    
    def leave(self, uid, gid):
	"""Let user "uid" leave group "gid" """

        #TODO: remove old group key?       
        if rediserver.srem("users_gid:"+gid, uid) and self.__addk(gid): print self.OK_MSG
        else: print self.KO_MSG
        return
		
    def addg(self, gid):
	"""Create a new group"""

	if rediserver.sadd("gids", gid):
            print self.OK_MSG
        else: print self.KO_MSG
        return
		
    def remg(self, gid):
	"""Delete a group and all keys it owns """

        if rediserver.sismember("gids", gid):

            # Delete keys
            for sha1code in rediserver.smembers("keys_gid:"+gid):
                self.remk(sha1code)
            rediserver.delete("keys_gid:"+gid)

            # Delete list of users
            rediserver.delete("users_gid:"+gid)

            # Delete gid from list of groups
            rediserver.srem("gids", gid)
            print self.OK_MSG

        else: print self.KO_MSG+": "+gid+" doesn't exist."
        return

    def listg(self):
        """ List groups """

        print rediserver.smembers("gids")
        return

    def listu(self):
        """ List users """

        print rediserver.smembers("uids")
        return

    def listk(self, gid):
        """ List all sha-1(key)s of group "gid" """

        print rediserver.smembers("keys_gid:"+gid)
        return

    def getk(self, gid):
        """ Get the sha-1 of the primary key for group "gid" """

        print rediserver.get("first_key_gid:"+gid)
        return
		
    def set_primary_key(self, gid, index):
        return
    

def main():
    if 'GATEWAY_INTERFACE' in os.environ:
        print "Content-Type: text/plain\n"
        # TODO: add Content-Length
        query = "scriptname" + os.environ['PATH_INFO'] # e.g.: "scriptname/listk/atlas"
        argv = query.split("/")
    else:
        argv = sys.argv

    if len(argv) == 1:
        print "Usage: ..."
        return

    # Start the connection to the redis server
    global rediserver
    rediserver = redis.StrictRedis(host='localhost', port=6379, db=0)
	
    # Read the command line and execute proper function
    cmd = Commands()
    getattr(cmd, argv[1])(*argv[2:])
	
    return

if __name__ == '__main__':
    main()
