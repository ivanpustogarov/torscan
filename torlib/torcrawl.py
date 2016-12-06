#!/usr/bin/env python

# Primitive Tor client to connect to a relay and check its connectivitity 
# to other relays.
#
# mainly written by Ralf-Philipp Weinmann <ralf@coderpunks.org>,
#
# placed in the public domain
#
# Requirements:
# Python (>= 2.4)
# m2crypto (>= 0.20.1)
# pyasn1 (>= 0.0.11)
# hashlib (included in Python >= 2.5)

import os, sys, time
import struct, base64, hashlib
import pyasn1
import socket
import binascii
import xorcpp

from M2Crypto import *
from torparams import *

import torcrypto

#CircID = 0x0102
#threading.init()

class TorException(Exception):
    pass

################################################################################

class TorCertificate:
    def callback(self, *args):
        pass

    def __init__(self, keybits = 1024, is_CA = True, issuer = None, signing_key = None):
        keypair = EVP.PKey()
        x509req = X509.Request()
        rsa = RSA.gen_key(1024, 65537, self.callback)
        keypair.assign_rsa(rsa)
        x509req.set_pubkey(keypair)
        name = x509req.get_subject()
        name.CN = TorCertificate.random_host_name(8, 20, "www.", ".net")
        pubkey = x509req.get_pubkey()
        sub = x509req.get_subject()
        #print sub
        cert = X509.X509()
        cert.set_version(2)
        cert.set_serial_number(BN.rand_range(2**31))
        cert.set_subject(sub)
        t = long(time.time()) + time.timezone
        not_before = ASN1.ASN1_UTCTIME()
        not_before.set_time(t)
        not_after = ASN1.ASN1_UTCTIME()
        not_after.set_time(t + TOR_CERTS_LIFETIME)
        cert.set_not_before(not_before)
        cert.set_not_after(not_after)
        if issuer == None:
            issuer = X509.X509_Name()
            issuer.CN = name.CN
        cert.set_issuer(issuer)
        cert.set_pubkey(pubkey) 
        if is_CA:
            ext = X509.new_extension('basicConstraints', 'CA:TRUE')
            cert.add_ext(ext)

        if signing_key:
            cert.sign(signing_key, 'sha1')
        else:
            cert.sign(keypair, 'sha1')
        self.cert = cert
        self.keypair = keypair

    @staticmethod
    def random_host_name(min_len, max_len, prefix, suffix):
        rand_len = BN.rand_range(max_len-min_len) + min_len
        randstr = base64.b32encode(os.urandom(rand_len))[0:rand_len].lower()
        return prefix + randstr + suffix
        
    @staticmethod
    def random_file_name(length, prefix, suffix):
        #rand_len = BN.rand_range(max_len-min_len) + min_len
        randstr = base64.b32encode(os.urandom(length))[0:length].lower()
        return prefix + randstr + suffix

################################################################################

class RelayCell:
    (BEGIN, DATA, CONNECTED, SENDME, EXTEND, EXTENDED, TRUNCATE, TRUNCATED,
     DROP, RESOLVE, RESOLVED, BEGIN_DIR) = range(1,13)

    def __init__(self, relay_cmd, stream_id, data):
        self.relay_cmd = relay_cmd
        self.recognized = 0
        self.stream_id = stream_id
        self.digest = 0
        self.length = len(data)
        self.data = data

    def pack(self):
        return struct.pack('!BHHLH498s', self.relay_cmd, self.recognized, self.stream_id,
                           self.digest, self.length, self.data)

    def unpack(self, cell_data):
        (self.relay_cmd, self.recognized, self.stream_id,
         self.digest, self.length, self.data) = struct.unpack('!BHHLH498s', cell_data)
        self.data = self.data[0:self.length]

    #def EXTEND_CELL(signing_key, onion_key, ip_address, port):
    @staticmethod
    def EXTEND_CELL(signing_key, onionskin, ip_address, port,id_fingerprint):
        #id_fingerprint = torcrypto.identity_fingerprint(signing_key)

        #(onionskin, x) = torcrypto.create_onion_skin(onion_key)
        data = socket.inet_aton(ip_address) + struct.pack('!H', port) + onionskin + id_fingerprint

        # streamID = 0 since RELAY_EXTEND is a control cell
        #extend_cell = RelayCell(RelayCell.EXTEND, 0, data)
        extend_cell = RelayCell(6, 0, data)
        return extend_cell


class TorCell:
    (PADDING, CREATE, CREATED, RELAY, DESTROY, CREATE_FAST, CREATED_FAST,
     VERSION, NETINFO, RELAY_EARLY) = range(10)

    def __init__(self, circuit_id = 0, command = 0, payload = [], length = None):
        self.circuit_id = circuit_id
        self.command = command
        self.payload = payload
        self.length = length

    def pack(self, versionCell = False):
        if not versionCell:
            return struct.pack('!HB509s', self.circuit_id, self.command, self.payload)
        else:
            return struct.pack('!HBH507s', self.circuit_id, self.command, self.length, 
                               self.payload)

    def unpack(self, cell_data, versionCell = False):
        if not versionCell:
            (self.circuit_id, self.command, self.payload) = struct.unpack('!HB509s', cell_data)            
        else:
            (self.circuit_id, self.command, 
             self.length, self.payload) = struct.unpack('!HB507s', cell_data)
            self.payload = self.payload[0:self.length]

################################################################################

class ORConnection:
    CERTS_UP_FRONT = 0
    RENEGOTIATION = 1
    BACKWARDS_COMPATIBLE = 2

    def __init__(self):
        self.ctx = SSL.Context('tlsv1')
        self.ctx.set_verify(0,depth=0)
        self.socket = SSL.Connection(self.ctx)
        ##################################
        #self.socket.set_socket_read_timeout(SSL.timeout(sec=5))
        
        ##################################
        self.socket.set_post_connection_check_callback(None)
        self.Kf = self.Kb = self.Df = self.Db = None
        self.buffer = ''
        pass

    def connect(self, srv_name, srv_port, identity_cert_filename = None, onion_cert_filename = None, onion_private_key_filename = None, handshake_type = CERTS_UP_FRONT):
        tor_cipher_list = 'DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:' \
                          'DHE-RSA-DES-CBC3-SHA:DHE-DSS-DES-CBC3-SHA'
                
        if handshake_type == self.CERTS_UP_FRONT:
            if (onion_cert_filename == None) or (onion_private_key_filename) == None or (identity_cert_filename == None):
                raise TorException("Trying to establish a TLS UP_FRONT connection but no certificates were provided!")
            #print "Doing certificates up front ... "
            self.ctx.load_cert(onion_cert_filename, onion_private_key_filename)
            self.ctx.load_client_CA(identity_cert_filename)
            self.socket.set_cipher_list(tor_cipher_list)
            #print "Connecting to the sever..."
            self.socket.connect((srv_name, srv_port))
            #print "Connected!"
            
        elif handshake_type == self.RENEGOTIATION:
            self.socket.set_cipher_list(tor_cipher_list + ':DHE-RSA-AES128-MD5')
            self.socket.connect((srv_name, srv_port))
            self.ctx.load_cert(onion_cert_filename, onion_private_key_filename)
            self.ctx.load_client_CA(identity_cert_filename)
            self.socket.renegotiate()
            # XXX need to exchange version cells here
        elif handshake_type == self.BACKWARDS_COMPATIBLE:
            # XXX not implemented yet
            pass
        else:
            raise TorException("unknown handshake type (%d)" % handshake_type)

    # write 
    def write_cell(self, cell):
        written = self.socket.write(cell.pack())
        return written
        
    def write_cells(self, cells_list):
        super_cell_packed = ''        
        for cell in cells_list:        
            super_cell_packed = super_cell_packed + cell.pack()
        #print "Trying ot write %d bytes" % len(super_cell_packed)
        written = self.socket.write(super_cell_packed)
        return written

    # read cell from connection
    def read_cell(self):
        cell = TorCell()
        data = ''
        #print "Bytes pending = {0}".format(self.socket.pending())
        if len(self.buffer) >= CELL_LEN:
            cell.unpack(self.buffer[0:CELL_LEN])
            self.buffer = self.buffer[CELL_LEN:]
            return cell
        
        try:
            #data = self.socket.read(CELL_LEN-len(self.buffer))
            data = self.socket.read(CELL_LEN*8)
        except SSL.SSLError as errno:
            print "SSLError exception caught after reading d bytes: {}; {}".format(len(data), errno)
            raise TorException("SSL ERROR")
            return None 
            
        if data != None:
            #print "Read bytes = {0}".format(len(data))
            self.buffer = self.buffer+data
            if len(self.buffer)<CELL_LEN:
                return None
            else:
                cell.unpack(self.buffer[0:CELL_LEN])        
                self.buffer = self.buffer[CELL_LEN:]
                return cell
        else:
            cell = None
        return cell
        

    # derive key material from K0
#    def derive_keys(self, K0):
#        tkdf = hashlib.sha1(K0)
#        K = ''
#        for i in range(5):
#            H = tkdf.copy()
#            H.update(chr(i))
#            K += H.digest()
#
#        # ''Df is used to seed the integrity-checking hash
#        #   for the stream of data going from the OP to the OR''
#        self.Df = K[HASH_LEN:2*HASH_LEN]
#        self.md_Df = hashlib.sha1(self.Df)
#        # ''Db seeds the integrity-checking hash for the data stream from 
#        #   the OR to the OP''
#        self.Db = K[2*HASH_LEN:3*HASH_LEN]
#        self.md_Db = hashlib.sha1(self.Db)
#        # ''Kf is used to encrypt the stream of data going from the OP 
#        #   to the OR''
#        self.Kf = K[3*HASH_LEN:HASH_LEN*3+CIPHER_LEN]
#        # ''Kb is used to encrypt the stream of data going from the OR 
#        #   to the OP''
#        self.Kb = K[3*HASH_LEN+CIPHER_LEN:3*HASH_LEN+2*CIPHER_LEN]
#        # reset counter value (forward direction)
#        self.f_aes_counter = 0
#        # reset counter value (backward direction)
#        self.b_aes_counter = 0
#        # ''KH is used in the handshake response to demonstrate knowledge of the
#        #   computed shared key''
#        return K[0:HASH_LEN] # KH


    def derive_keys(self,K0):
        # ''Df is used to seed the integrity-checking hash
        #   for the stream of data going from the OP to the OR''
        self.Df = hashlib.sha1(K0+'\x01').digest()#K[20:40]
        self.md_Df = hashlib.sha1(self.Df)
        # ''Db seeds the integrity-checking hash for the data stream from 
        #   the OR to the OP''
        self.Db = hashlib.sha1(K0+'\x02').digest()#K[40:60]
        self.md_Db = hashlib.sha1(self.Db)
        # ''Kf is used to encrypt the stream of data going from the OP 
        #   to the OR''
        tmp = hashlib.sha1(K0+'\x03').digest()+hashlib.sha1(K0+'\x04').digest()
        self.Kf = tmp[0:16]#K[60:76]
        # ''Kb is used to encrypt the stream of data going from the OR 
        #   to the OP''
        self.Kb = tmp[16:32]#K[76:92]
        # reset counter value (forward direction)
        self.f_aes_counter = 0
        # reset counter value (backward direction)
        self.b_aes_counter = 0
        # ''KH is used in the handshake response to demonstrate knowledge of the
        #   computed shared key''
        return hashlib.sha1(K0+'\x00').digest() # KH



    # perform a handshake with the connected OR using a CREATE cell
    def do_handshake(self, onion_key):
        print "Creating onion skin..."        
        (onion_skin, x) = torcrypto.create_onion_skin(onion_key)
        print "Created!"
        print "Creating CREATE cell..."        
        cell = TorCell(0, TorCell.CREATE, onion_skin)
        print "Created!"
        print "We are sending CREATE cell to omicron now!"
        self.write_cell(cell)
        reply_cell = self.read_cell()
        print "We got a created cell with length = {0} and command = {1}".format(reply_cell.length,reply_cell.command)
        if reply_cell.command != TorCell.CREATED:
            raise TorException("unexpected cell type received in reply to CREATE (%d)." % 
                               reply_cell.command)
        Y = torcrypto.binstr2num_be(reply_cell.payload[0:DH_LEN])
        KH_check = reply_cell.payload[DH_LEN:DH_LEN + HASH_LEN]
        K0 = torcrypto.modexp(Y, x, TOR_DH_PRIME)
        KH = self.derive_keys(torcrypto.num2binstr_be(K0))
        if KH != KH_check:
            print "KH  =", binascii.hexlify(KH)
            print "KH' =", binascii.hexlify(KH_check)
            raise TorException("KH in CREATED cell is incorrect, DH key exchange failed!")

    # perform a handshake with the connected OR using a CREATE_FAST cell
    def do_handshake_fast(self,CircID):
        X = os.urandom(HASH_LEN)
        self.write_cell(TorCell(CircID, TorCell.CREATE_FAST, X))
        reply_cell = self.read_cell()
        if reply_cell.command != TorCell.CREATED_FAST:
            raise TorException("unexpected cell type received in reply to CREATE_FAST (%d)." %
                               reply_cell.command)
        Y = reply_cell.payload[0:HASH_LEN]
        KH_check = reply_cell.payload[HASH_LEN:2*HASH_LEN]
        KH = self.derive_keys(X + Y)
        if KH != KH_check:
            print "KH  =", binascii.hexlify(KH)
            print "KH' =", binascii.hexlify(KH_check)
            raise TorException("response KH in CREATED_FAST cell is invalid!")
        
    def update_keys(self, X, reply_cell):
        Y = reply_cell.payload[0:HASH_LEN]
        KH_check = reply_cell.payload[HASH_LEN:2*HASH_LEN]
        KH = self.derive_keys(X + Y)
        if KH != KH_check:
            print "KH  =", binascii.hexlify(KH)
            print "KH' =", binascii.hexlify(KH_check)
            raise TorException("response KH in CREATED_FAST cell is invalid!")
            
    def switch_keys(self,Kf,Kb,Df,Db,f_aes_counter,b_aes_counter):
        self.Kf = Kf
        self.Kb = Kb
        self.Df = Df
        self.md_Df = hashlib.sha1(self.Df)
        self.Db = Db
        self.md_Db = hashlib.sha1(self.Db)
        self.f_aes_counter = f_aes_counter
        self.b_aes_counter = b_aes_counter
        
        
    def write_create_cell(self, CircID):
         X = os.urandom(HASH_LEN)
         written = self.write_cell(TorCell(CircID, TorCell.CREATE_FAST, X))
         return written
         

    def crypt_cell(self, relay_cell, forward_direction, encrypt):
        if self.Kf == None or self.Kb == None or self.Df == None or self.Db == None:
            raise TorException("no handshake performed on connection yet.")

        if forward_direction:
            key = self.Kf
            ctr = self.f_aes_counter
            md = self.md_Df.copy()
        else:
            key = self.Kb
            ctr = self.b_aes_counter
            md = self.md_Db.copy()

        (cipher_stream, ctr) = torcrypto.generate_cipherstream(key, ctr, CELL_LEN)
        # update counter
        if forward_direction:
            self.f_aes_counter = ctr
        else:
            self.b_aes_counter = ctr

        if encrypt:
            relay_cell.recognized = 0
            relay_cell.digest = 0
            md.update(relay_cell.pack())
            md_clone = md.copy()
            relay_cell.digest = struct.unpack('!L', md.digest()[0:4])[0]
            relay_cell.unpack(xorcpp.xorcpp_inplace(relay_cell.pack(), cipher_stream)[0:509] )
        else:
            relay_cell.unpack(xorcpp.xorcpp_inplace(relay_cell.pack(), cipher_stream)[0:509] )
            if relay_cell.recognized != 0:
                relay_cell = None
                return relay_cell
            check_digest = relay_cell.digest
            relay_cell.digest = 0
            md.update(relay_cell.pack())
            md_clone = md.copy()
            if struct.unpack('!L', md.digest()[0:4])[0] != check_digest:
                relay_cell = None
                print "digest verification failed!!!!!"

        if forward_direction:
            self.md_Df = md_clone
        else:
            self.md_Db = md_clone

        return relay_cell    
    
    def encrypt_cell(self, relay_cell, forward_direction=True):
        return self.crypt_cell(relay_cell, forward_direction, encrypt=True)

    def decrypt_cell(self, relay_cell, forward_direction=False):
        return self.crypt_cell(relay_cell, forward_direction, encrypt=False)



################################################################################

# This is just to test the functionality of the module
def main():
    tor_ca_cert = TorCertificate(1024)
    tor_client_cert = TorCertificate(1024, False, tor_ca_cert.cert.get_issuer(), tor_ca_cert.keypair)
    
    tor_ca_cert.cert.save_pem('tor_ca.pem')
    tor_ca_cert.keypair.save_key('tor_ca.key', cipher=None)
    tor_client_cert.cert.save_pem('tor_client.pem')
    tor_client_cert.keypair.save_key('tor_client.key', cipher=None)

    orconn = ORConnection()
    if len(sys.argv) > 2:
        orconn.connect(sys.argv[1], int(sys.argv[2]))
    else:
        orconn.connect(default_hostname, default_port)

    orconn.do_handshake_fast()

    extend_cell = RelayCell.EXTEND_CELL(signing_key4, onion_key4, '127.0.0.1', 443)
    encrypted_cell = TorCell(CircID, TorCell.RELAY, orconn.encrypt_cell(extend_cell).pack())
    orconn.write_cell(encrypted_cell)
    reply_cell = orconn.read_cell()
    print reply_cell.command
    print reply_cell.payload[0].encode('hex')
    
    print "Done!"

if __name__ == "__main__":
  main()


