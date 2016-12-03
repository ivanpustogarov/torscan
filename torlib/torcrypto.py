# Copyright (c) 2014-2015 Ralf-Philipp Weinmann
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from M2Crypto import *
from pyasn1.codec.der import (decoder as der_decoder)
from pyasn1.type import univ
import hashlib, re, base64, struct, os, binascii

from torparams import *

# (compiled) regular expression to extract base64 encoded date from
# RSA PKCS#1 public keys
RSA_PKCS1_PUBKEY_RE = re.compile('-----BEGIN RSA PUBLIC KEY-----\n(.*)\n'
                                 '-----END RSA PUBLIC KEY-----', 
                                 re.MULTILINE | re.DOTALL)

class InvalidPKCS1Exception(Exception):
    pass

def modexp (g, e, p):
    "Perform modular exponentation g^e mod p (using square and multiply)"
    result = 1
    while e != 0:
        if e & 1:
            result = (result * g) % p
        e >>= 1
        g = (g * g) % p
    return result

def binstr2num_be(x):
    "Converts a string of bytes x in big endian format to an integer"
    n = 0
    for c in x:
        n <<= 8
        n += ord(c)
    return n

def num2binstr_be(n):
    "Converts an integer n to a string of bytes in big endian format"
    binstr = ''
    while n:
        binstr += chr(n & 255)
        n >>= 8
    return binstr[::-1]

def xor(x, y):
    "Compute the XOR of two strings x, y"
    return str(bytearray([a^b for a, b in zip(bytearray(x), bytearray(y))]))

def long_to_mpi(num):
    "Converts a python integer or long to OpenSSL MPInt used by M2Crypto."
    h = hex(num)[2:] # strip leading 0x in string
    if len(h) % 2 == 1:
        h = '0' + h # add leading 0 to get even number of hexdigits
        return m2.bn_to_mpi(m2.hex_to_bn(h)) # convert using OpenSSL BinNum

def create_onion_skin(onion_key):
    "Create a Tor onion skin for public key onion_key"
    rsa = load_pkcs1_rsa_pubkey(onion_key)
    # ''As an optimization, implementations SHOULD choose DH private keys (x) of
    # 320 bits.''
    x = 2 + BN.rand_range(2 ** 320)
    X = num2binstr_be(modexp(TOR_DH_GEN, x, TOR_DH_PRIME))
    return (hybrid_encrypt(X, rsa), x)
    
#def generate_cipherstream(cipherkey, counter, len):
#    "Run AES128-CTR with given counter and cipherkey to generate len bytes of cipherstream"
#    aes_ecb = EVP.Cipher(alg='aes_128_ecb', key=cipherkey, op=1, iv='')
#    ctr_stream = bytearray()
#    for i in range((len+CIPHER_LEN-1)/CIPHER_LEN):
#        ctr_stream += struct.pack("!QQ", counter >> 64, 
#                                  counter & 0xffffffffffffffff)
#        counter += 1
#
#    cipher_stream = bytearray(aes_ecb.update(ctr_stream))
#    if len % CIPHER_LEN == 0:
#        return (cipher_stream, counter)
#    else:
#        return (cipher_stream[0:len], counter)
        
        
ctr_stream0 = '000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000060000000000000000000000000000000700000000000000000000000000000008000000000000000000000000000000090000000000000000000000000000000a0000000000000000000000000000000b0000000000000000000000000000000c0000000000000000000000000000000d0000000000000000000000000000000e0000000000000000000000000000000f000000000000000000000000000000100000000000000000000000000000001100000000000000000000000000000012000000000000000000000000000000130000000000000000000000000000001400000000000000000000000000000015000000000000000000000000000000160000000000000000000000000000001700000000000000000000000000000018000000000000000000000000000000190000000000000000000000000000001a0000000000000000000000000000001b0000000000000000000000000000001c0000000000000000000000000000001d0000000000000000000000000000001e0000000000000000000000000000001f'.decode('hex')        
def generate_cipherstream(cipherkey, counter, len):
    "Run AES128-CTR with given counter and cipherkey to generate len bytes of cipherstream"
    aes_ecb = EVP.Cipher(alg='aes_128_ecb', key=cipherkey, op=1, iv='')
    counter = 32
    cipher_stream = aes_ecb.update(ctr_stream0)
    return (cipher_stream, counter)
        
        
def hybrid_encrypt(M, rsa_object):
    "Encrypt message M using Tor hybrid encryption given a M2Crypto.RSA rsa_object"
    if len(M) < PK_ENC_LEN - PK_PAD_LEN:
        return rsa_object.public_encrypt(M, RSA.pkcs1_oaep_padding)

    K = os.urandom(KEY_LEN)
    M1 = M[0:PK_ENC_LEN - PK_PAD_LEN - KEY_LEN]
    M2 = M[PK_ENC_LEN - PK_PAD_LEN - KEY_LEN:]
    C1 = rsa_object.public_encrypt(K + M1, RSA.pkcs1_oaep_padding)
    (cipherstream, counter) = generate_cipherstream(K, 0, len(M2))
    C2 = xor(cipherstream, bytearray(M2))
    return C1 + C2

def pkcs1_rsa_pubkey_pem2der(pubkey):
    "Convert a RSA PKCS#1 public key in PEM format to DER format"
    if '\r' in pubkey:
        pubkey.replace('\r', '')
    #print pubkey
    pkcs1_match = RSA_PKCS1_PUBKEY_RE.search(pubkey)
    if not pkcs1_match:
        print pubkey
        raise InvalidPKCS1Exception('Not a RSA PKCS1 public key')
    return pkcs1_match.group(1).decode('base64')

def identity_fingerprint(pubkey, as_pem=True):
    "Compute a fingerprint of a public key (in PEM or DER format)"
    pubkey_der = pkcs1_rsa_pubkey_pem2der(pubkey) if as_pem else pubkey
    H = hashlib.sha1()
    H.update(pubkey_der)
    return H.digest()

def load_pkcs1_rsa_pubkey(pubkey, as_pem = True):
    "Generate a M2Crypto.RSA instance from a RSA PKCS#1 public key"
    pubkey_der = pkcs1_rsa_pubkey_pem2der(pubkey) if as_pem else pubkey

    (n, e), unused = der_decoder.decode(pubkey_der)
    if n.__class__ != univ.Integer or e.__class__ != univ.Integer:
        raise InvalidPKCS1Exception('type mismatch in PKCS1 ASN.1 structure')
    # cast n and e to OpenSSL MPints for M2Crypto before making pubkey.
    return RSA.new_pub_key((long_to_mpi(int(e)), long_to_mpi(int(n))))
