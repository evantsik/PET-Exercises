#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)


    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    aes = Cipher("aes-128-gcm")

    try:
    	plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)
    except:
    	raise Exception("Cipher: decryption failed.")

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x == None and y == None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    xr, yr = None, None
    if x0 is None and y0 is None:
    	xr, yr = x1, y1
    elif x1 is None and y1 is None:
    	xr, yr = x0, y0
    elif (x0 != x1) or (y0 != y1):
    	try:
    		left, right = y0 - y1, (x0 - x1).mod_inverse(p)
    		lam = (left*right).mod(p)
    		xr = ((lam *lam)-x1-x0).mod(p)
    		yr = (lam.mod_mul(x1-xr, p)).mod_sub(y1,p)
    	except:
    		return (None, None)
    else:
    	raise Exception("EC Points must not be equal")
    
    return (xr, yr)

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """  

    # ADD YOUR CODE BELOW
    xr, yr = None, None
    if x is None and y is None:
    	return None,None

    lam = (( 3*x*x + a) * ((2 * y).mod_inverse(p)) ).mod(p)
    xr  = (lam *lam - 2 * x).mod(p)
    yr = (lam.mod_mul(x-xr, p)).mod_sub(y,p)
    
    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
		if scalar.is_bit_set(i) == 1:
			Q = point_add(a,b,p,Q[0],Q[1],P[0],P[1])
		P = point_double(a,b,p,P[0],P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        if scalar.is_bit_set(i) == 0:
        	R1 = point_add(a,b,p,R0[0],R0[1],R1[0],R1[1])
        	R0 = point_double(a,b,p,R0[0],R0[1])
        else:
        	R0 = point_add(a,b,p,R0[0],R0[1],R1[0],R1[1])
        	R1 = point_double(a,b,p,R1[0],R1[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")
    ##digest/hash
    digest = sha256(plaintext).digest()
    ##sign
    sig = do_ecdsa_sign(G, priv_sign, digest)

    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")
    digest = sha256(plaintext).digest()
    res = do_ecdsa_verify(G, pub_verify, sig, digest)

    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """
    """
	#encrypt with 256 aes because of key length <= 28, 4 byte pad needed.
	#This was the first implementation because i believe its more secure but i sticked to the other to use the already implemented encrypt message of the previoous task2
    padded_key = shared_key.binary()
    while len(padded_key) < 32:
    	padded_key += b'0'
    
    plaintext = message.encode("utf8")
    aes = Cipher("aes-256-gcm")
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(padded_key, iv, plaintext)
	"""
	#fresh DH key
    G, priv_dec, pub_enc = dh_get_key()
    #fresh shared key. The shared secret is the x co-ordinate of the calculated point dAdBG.
    shared_key, shared_y = (priv_dec*pub).get_affine()
    shared_key = shared_key.binary()
    shared_key_16 = shared_key[0:16]
    iv, ciphertext, tag = encrypt_message(shared_key_16, message)
    #signature
    sig = None
    if not (aliceSig is None) :
        sig = ecdsa_sign(G, aliceSig, message)
    
    return [iv, ciphertext , tag, pub_enc, sig];


def dh_decrypt(priv, ciphertext, aliceVer = None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""
    
    shared_key, shared_y = (priv*ciphertext[3]).get_affine()
    shared_key = shared_key.binary()
    shared_key_16 = shared_key[0:16]
    #decrypt with 256 aes
    """while len(padded_key) < 32:
    	padded_key += b'0'
    	
    aes = Cipher("aes-256-gcm")
	"""

    plain = decrypt_message(shared_key_16,ciphertext[0],ciphertext[1],ciphertext[2])
    #signature verify
    ver = False
    if not (aliceVer is None) and not (ciphertext[4] is None):
        ver = ecdsa_verify(aliceVer[0], aliceVer[1], plain, ciphertext[4])

    return [plain, ver]  


## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 
from pytest import raises
from os import urandom
def test_encrypt():
    G, Bpriv, Bpub = dh_get_key()
    message = u"Hello World!"
    ciphertext = dh_encrypt(Bpub,message)
    
    assert len(ciphertext[0]) == 16
    assert len(ciphertext[1]) == len(message)
    assert len(ciphertext[2]) == 16

def test_decrypt():
    G, Bpriv, Bpub = dh_get_key()
    G, Apriv, Apub = dh_get_key()
    message = u"Hello World!"
    ciphertext = dh_encrypt(Bpub,message,Apriv)
    
    assert len(ciphertext[0]) == 16
    assert len(ciphertext[1]) == len(message)
    assert len(ciphertext[2]) == 16

    Verify_key = [G,Apub]
    m = dh_decrypt(Bpriv,ciphertext,Verify_key)
    assert m[0] == message
    ##signature must be valid/true
    assert m[1]

def test_fails():
    G, Kpriv, Kpub = dh_get_key()
    G, Apriv, Apub = dh_get_key()
    message = u"Hello World!"
    ciphertext = dh_encrypt(Kpub, message)

    dummy = list(ciphertext)
    dummy[1] = urandom(len(dummy[1]))
    with raises(Exception) as excinfo:
        dh_decrypt(Kpriv,dummy)
    assert 'decryption failed' in str(excinfo.value)
    dummy = list(ciphertext)
    dummy[2] = urandom(len(dummy[2]))
    with raises(Exception) as excinfo:
        dh_decrypt(Kpriv,dummy)
    assert 'decryption failed' in str(excinfo.value)
    dummy = list(ciphertext)
    dummy[0] = urandom(len(dummy[0]))
    with raises(Exception) as excinfo:
        dh_decrypt(Kpriv,dummy)
    assert 'decryption failed' in str(excinfo.value)
    
    Verify_key = [G,Apub]
    m = dh_decrypt(Kpriv,ciphertext,Verify_key)
    ##signature must be false since we didnt sign
    assert m[1] == False

    m = dh_decrypt(Kpriv,ciphertext)
    ##signature must be false since we didnt sign and we didnt verify
    assert m[1] == False
   

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.
import time
def time_scalar_mul():
   """ time1 = time.clock()
    
    from pytest import raises
    from petlib.ec import EcGroup, EcPt
    G = EcGroup(713) # NIST curve
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()

    r = G.order().random()

    gx2, gy2 = (r*g).get_affine()


    x2, y2 = point_scalar_multiplication_double_and_add(a, b, p, gx0, gy0, r)
    assert is_point_on_curve(a, b, p, x2, y2)
    assert gx2 == x2
    assert gy2 == y2

    time2 = time.clock()
    print(time2-time1)
    assert time2 == time1"""