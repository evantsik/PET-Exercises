#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

###########################
# Group Members: TODO
###########################


from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify

def aes_ctr_enc_dec(key, iv, input):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption. 
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in 
    fact the same operations.
    """
    
    aes = Cipher("AES-128-CTR") 

    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()

    return output

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#


## This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key', 
                                                   'hmac', 
                                                   'address', 
                                                   'message'])

from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher

def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix. 

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:
    	""" print(len(msg.hmac))
    	print(len(msg.address))
    	print(len(msg.message))""" 
        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not len(msg.hmac) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)        
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the address and the message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)
        
        
def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an hmac (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    ## ADD CODE HERE
    ## First get a shared key
    shared_element = private_key * public_key
    key_material = sha512(shared_element.export()).digest()

    # Use different parts of the shared key for different operations
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]

    ## Decrypt the address and the message
    iv = b"\x00"*16

    address = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    ## Create the HMAC
    h = Hmac(b"sha512", hmac_key)        
    h.update(address)
    h.update(message)
    hmac = h.digest()
    hmac = hmac[:20]

    return OneHopMixMessage(client_public_key, hmac, address, message)

    

#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

from petlib.ec import Bn

# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key', 
                                                   'hmacs', 
                                                   'address', 
                                                   'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be 
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn: 
        - it derives a shared key (using its private_key), 
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message. 
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not isinstance(msg.hmacs, list) or \
               not len(msg.hmacs[0]) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)
            #print(other_mac)

        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()
        #print(expected_mac[:20])
        #print(msg.hmacs[0])
        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the hmacs, address and the message
        aes = Cipher("AES-128-CTR") 

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]
        
        # Decrypt address & message
        iv = b"\x00"*16
        
        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    hmacs = []
    mackeys = []
    mkeys = []
    akeys = []
    aciphers = []
    mciphers = []
    address_cipher = None
    message_cipher = None
    shared_element = None
    for i in range(len(public_keys)):
    	## First get a shared key
    	
        shared_element = private_key * public_keys[i]
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        mackeys += [hmac_key]
        akeys += [address_key]
        mkeys += [message_key]
        # Extract a blinding factor for the new private key
        blinding_factor = Bn.from_binary(key_material[48:])
        private_key = blinding_factor * private_key


    for i in range(len(public_keys)):

    	# Encrypt address & message 
        iv = b"\x00"*16
        
        if i==0:
        	address_cipher = aes_ctr_enc_dec(akeys[len(public_keys)-1-i], iv, address_plaintext)
        	message_cipher = aes_ctr_enc_dec(mkeys[len(public_keys)-1-i], iv, message_plaintext)
        else:
        	address_cipher = aes_ctr_enc_dec(akeys[len(public_keys)-1-i], iv, address_cipher)
        	message_cipher = aes_ctr_enc_dec(mkeys[len(public_keys)-1-i], iv, message_cipher)

        mciphers += [message_cipher]
        aciphers += [address_cipher]


    for i in range(len(public_keys)):

        # encrypt hmacs. It is done seperately since i need all the ciphertext to calculate the macs correctly
        # i use the mac keys in reverse order because for the last ciphertext,i have to use the 1st key
        new_hmacs = []
        for j, other_mac in enumerate(hmacs):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", j, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(mackeys[len(public_keys)-1-i], iv, other_mac)
            new_hmacs += [hmac_plaintext]  


        h = Hmac(b"sha512", mackeys[len(public_keys)-1-i])
        # calculating the new digest
        new_hmacs = new_hmacs[::-1]
        for other_mac in reversed(new_hmacs):
                h.update(other_mac) 

        h.update(aciphers[i])
        h.update(mciphers[i])
        
        digest  = h.digest()
        digest	= digest[:20]

        new_hmacs += [digest]
        hmacs = new_hmacs[::-1]

    hmacs = new_hmacs[::-1]

    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)



#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.

import random

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    ## Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample( others, threshold_size))
        receivers = sorted(random.sample( all_users, threshold_size))

        trace += [(senders, receivers)]

    ## Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample( others, threshold_size-1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample( all_users, threshold_size-1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter

def analyze_trace(trace, target_number_of_friends, target=0):
    """ 
    Given a trace of traffic, and a given number of friends, 
    return the list of receiver identifiers that are the most likely 
    friends of the target.
    """
    possible_friends = Counter()
    #find all the targets that alice sent messages to alongside with the messages she sent to them
    for senders, receivers in trace:
        if target in senders:
            for receiver in receivers:
                possible_friends[receiver] +=1

    friends = []
    #from the possible friends take the first n (target_number_of_friends) most common. 
    #.most_common returns the pairs sorted (according to the frequency) so the first friend will be the most common one etc.
    for friend,frequency in possible_friends.most_common(target_number_of_friends):
    	friends += [friend]

    return friends


## TASK Q1 (Question 1): The mix packet format you worked on uses AES-CTR with an IV set to all zeros. 
#                        Explain whether this is a security concern and justify your answer.

""" The main problem is that when we use the same key,iv pair to encrypt 2 messages.
	So for example if both adrress and message used the same key, the ciphertexts could 
	compromise the security. Also the iv shouldn't be a fixed value (its like nonce).

	Generally in CTR mode we combine an IV (with a counter concatenated at the end) with the key and then the result will be
	XORed with the plaintext. The same combination of IV and Key will produce the same byte sequence. Therefore the security
	breaks under chosen-plaintext attack. Therefore, we should use a random iv in every encryption (and probably another key).
	
	Also we should note that every IV value is equally secure. That's true for IV=0, if that's never re-used (with the same key).
 """


## TASK Q2 (Question 2): What assumptions does your implementation of the Statistical Disclosure Attack 
#                        makes about the distribution of traffic from non-target senders to receivers? Is
#                        the correctness of the result returned dependent on this background distribution?

""" Our implementation assumes that we will have a normal distribution, therefore we won't have "a peak" (non-target senders
	to send many messages to a single reciever). The correctness of our result depends on this assumption. The main problem is that
	in our trace we have senders,recievers (more than one in both sets). So for every pair, where Alice is one of the senders, we
	add all of the recievers as possible friends. Therefore in case the distribution is not normal we might had a pairs like:
	senders(0,1,2,3,4), recievers(3,5,5,5,5). (lets say that Alice(0) sent to 3). We might then think that Alice's friend is 5 when in
	fact her friend is 3. So in generall if we have a bad distribution, we will have wrong results.
	  """

