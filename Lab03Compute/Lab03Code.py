#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 03
#
# Basics of Privacy Friendly Computations through
#         Additive Homomorphic Encryption.
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Setup, key derivation, log
#           Encryption and Decryption
#

###########################
# Group Members: TODO
###########################


from petlib.ec import EcGroup

def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen(params):
   """ Generate a private / public key pair """
   (G, g, h, o) = params
   priv = G.order().random()
   pub  = priv * g

   return (priv, pub)

def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

    c = []
    k = params[0].order().random()
    c += [k*params[1]]
    c += [k*pub + m*params[2]]


    return c

def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret

_logh = None
def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    (G, g, h, o) = params

    # Initialize the map of logh
    if _logh == None:
        _logh = {}
        for m in range (-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]

def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a , b = ciphertext
    (G, g, h, o) = params
    
    inverse = (priv * a).pt_neg()
    hm = b + inverse

    return logh(params, hm)

#####################################################
# TASK 2 -- Define homomorphic addition and
#           multiplication with a public value
# 

def add(params, pub, c1, c2):
    """ Given two ciphertexts compute the ciphertext of the 
        sum of their plaintexts.
    """
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

    (G, g, h, o) = params
    a1 , b1 = c1
    a2 , b2 = c2

    a3 = a1.pt_add(a2)
    b3 = b1.pt_add(b2)

    c3 = a3, b3

    return c3

def mul(params, pub, c1, alpha):
    """ Given a ciphertext compute the ciphertext of the 
        product of the plaintext time alpha """
    assert isCiphertext(params, c1)

    (G, g, h, o) = params
    a1 , b1 = c1

    a3 = a1.pt_mul(alpha)
    b3 = b1.pt_mul(alpha)

    c3 = a3, b3
    return c3

#####################################################
# TASK 3 -- Define Group key derivation & Threshold
#           decryption. Assume an honest but curious 
#           set of authorities.

def groupKey(params, pubKeys=[]):
    """ Generate a group public key from a list of public keys """
    (G, g, h, o) = params

    pub = pubKeys[0]
    for key in  pubKeys:
        if pub == key:
            continue;
        pub += key

    return pub

def partialDecrypt(params, priv, ciphertext, final=False):
    """ Given a ciphertext and a private key, perform partial decryption. 
        If final is True, then return the plaintext. """
    assert isCiphertext(params, ciphertext)
    
    a1 , b = ciphertext
    inverse = (priv * a1).pt_neg()
    b1 = b + inverse

    if final:
        return logh(params, b1)
    else:
        return a1, b1

#####################################################
# TASK 4 -- Actively corrupt final authority, derives
#           a public key with a known private key.
#

def corruptPubKey(params, priv, OtherPubKeys=[]):
    """ Simulate the operation of a corrupt decryption authority. 
        Given a set of public keys from other authorities return a
        public key for the corrupt authority that leads to a group
        public key corresponding to a private key known to the
        corrupt authority. """
    (G, g, h, o) = params
    
    pub = priv*g
    for key in OtherPubKeys:
        pub -= key

    return pub

#####################################################
# TASK 5 -- Implement operations to support a simple
#           private poll.
#

def encode_vote(params, pub, vote):
    """ Given a vote 0 or 1 encode the vote as two
        ciphertexts representing the count of votes for
        zero and the votes for one."""
    assert vote in [0, 1]

    (G, g, h, o) = params
    if vote:
        v0 = encrypt(params,pub,0)
        v1 = encrypt(params,pub,1)
    else:
        v0 = encrypt(params,pub,1)
        v1 = encrypt(params,pub,0)

    return (v0, v1)

def process_votes(params, pub, encrypted_votes):
    """ Given a list of encrypted votes tally them
        to sum votes for zeros and votes for ones. """
    assert isinstance(encrypted_votes, list)
    tv0 = None
    tv1 = None
    for v0, v1 in encrypted_votes:
        if tv0 is None:
            tv0 = v0
            tv1 = v1
            continue;
        tv0 = add(params,pub,tv0,v0)
        tv1 = add(params,pub,tv1,v1)

    return tv0, tv1

def simulate_poll(votes):
    """ Simulates the full process of encrypting votes,
        tallying them, and then decrypting the total. """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1

###########################################################
# TASK Q1 -- Answer questions regarding your implementation
#
# Consider the following game between an adversary A and honest users H1 and H2: 
# 1) H1 picks 3 plaintext integers Pa, Pb, Pc arbitrarily, and encrypts them to the public
#    key of H2 using the scheme you defined in TASK 1.
# 2) H1 provides the ciphertexts Ca, Cb and Cc to H2 who flips a fair coin b.
#    In case b=0 then H2 homomorphically computes C as the encryption of Pa plus Pb.
#    In case b=1 then H2 homomorphically computes C as the encryption of Pb plus Pc.
# 3) H2 provides the adversary A, with Ca, Cb, Cc and C.
#
# What is the advantage of the adversary in guessing b given your implementation of 
# Homomorphic addition? What are the security implications of this?

""" The Adversary can be 100% sure about b. Given the ciphertexts Ca Cb Cc the Adversary 
	can compute the Homomorphic addition of Ca+Cb and Cb+Cc which are equal to the encryption 
	of Pa plus Pb and Pb plus Pc respectively. One of the two additions will produce C and the 
	Adversary will learn the value of b.

	The security implications of this is that we should be very careful even of what ciphertexts
	we send. An Adversary has more than one ways to find/guess a secret. Even if the ciphertexts
	cannot be 'broken' individually, a compossision of them might reveal secret information to the attacker."""

###########################################################
# TASK Q2 -- Answer questions regarding your implementation
#
# Given your implementation of the private poll in TASK 5, how
# would a malicious user implement encode_vote to (a) distrupt the
# poll so that it yields no result, or (b) manipulate the poll so 
# that it yields an arbitrary result. Can those malicious actions 
# be detected given your implementation?

""" a) A malicious user can implement encode_vote with  only two lines :
	v0 = encrypt(params,pub,0); v1 = encrypt(params,pub,0) and in this implementation it will be like 
	all users didn't vote at all. So when we count the votes it will be like no one has voted => the poll will
	yield no results.

	b) A malicious user can implement encode_vote to yield an arbitrary result by adding a line like :
	vote = random[0-1] at the beginning of the function. In this way every vote will be randomly 0 or 1 and 
	the result will be arbitrary.

	Those malicious activities cannot be detected in my implementation.
	First of all given that the malicious user controls the implementation on encode_vote, my implementation of
	this function doesn't matter at all.
	If we guess that I am the one to implement the process_votes and the malicious user implements the encode_vote,
	there is a way to detect the malicious activity. I should add a check in my process_votes to determine that for 
	every pair v0,v1 => v0 != v1. That solution works for (a) where all the votes are turned to 0. For (b) there is no
	way to detect the malicious activity as long as the votes (as they are) are only processed by the function that the
	malicious user implements."""
