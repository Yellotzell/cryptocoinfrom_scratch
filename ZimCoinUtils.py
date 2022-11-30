import struct,binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import time
from functools import partial
import multiprocessing 
from multiprocessing import pool
import random
import pandas as pd



################################
##### Code for Transactions ####
################################


def public_key_bytes(private_key):
    """
    Creates a public key from a Hazmat private key object

    Parameters
    ----------
    private_key : Hazmat object
        a private key object


    Returns
    -------
    a public key : bytes
       a public key in bytes format tha derives from the inpyt private key
    """
    return  (private_key.public_key()
                        .public_bytes(encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))



def address(private_key):
    """
    Generates a users address by applying SHA1 on the public key bytes format

    Parameters
    ----------
    private_key : Hazmat object
        a private key object


    Returns
    -------
    address : bytes
       a public key in bytes format tha derives from the input private key
    """

    digest = hashes.Hash(hashes.SHA1())
    digest.update(public_key_bytes(private_key))
    return digest.finalize()


def user_signature(private_key, *args):
    """
    Signs a list of data by using a Hazmat private key object

    Parameters
    ----------
    private_key : Hazmat object
        a private key object
    args: bytes, int
        the data to be signed. If the data are in int format are
        


    Returns
    -------
    a public key : bytes
       a public key in bytes format tha derives from the input private key
    """
    data = []
    for arg in args:
        if not isinstance(arg, bytes):
            arg = struct.pack('<Q', arg)
        data.append(arg)
    signature = (private_key
                          .sign(b''.join(data), 
                                ec.ECDSA(hashes.SHA256())))
    return signature

def update_hash(*args):
    """
    Hashes a list of data

    Parameters
    ----------
    args: bytes, int
        the data to be signed. If the data are in int format are
        
    Returns
    -------
    hashed data : bytes
       a bytes representation of the input data
    """
    data = []
    for arg in args:
        if not isinstance(arg, bytes):
            arg = struct.pack('<Q', arg)
        data.append(arg)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b''.join(data))
    return digest.finalize()

class user_pk:
    """
    A class to represent a transaction between zimcoin users.

    ...

    Attributes
    ----------
    name : str, optional
        the zimcoin user's name (default is None)


    Methods
    -------
    None
    """

    def __init__(self, name=None):
        """
        Constructs an elliptic curve private key for the user_pk object.

        If the argument 'additional' is passed, then it is appended after the main info.

        Parameters
        ----------
        name : str, optional
            the zimcoin user's name (default is None)
        
        private_key : Hazmat object
            a zimcoin user's private key

        """
        if name == None:
            self.name = ""
        else:
            self.name = name
        # Making private key inaccessible outside this class 
        # by adding a dunder in the front
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    def __str__(self):
            return (f"Name: {self.name}\nAddress: {self.private_key}".format(self=self))



class Transaction:
    """
    A class to represent a transaction between zimcoin users.

    ...

    Attributes
    ----------
    sender_hash : bytes
        the  address of a zimcoin user that is willing to send money
    recipient_hash : bytes
        the  address of a zimcoin user to recieve money
    sender_public_key : bytes
        the public key of a zimcoin user that is willing to send money
    amount : int
        the amount of zimcoins to be transfered including fee
    fee : int
        the amount of zimcoins to be paid from the sended as a fee for a transaction
    nonce : int
        the number of the last sender's transaction on the blockchain
    txid : bytes
        the transaction id



    Methods
    -------
    verify(sender_balance, sender_previous_nonce):
        Verifies transaction.
    """

    def __init__(self, sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, sender_signature, txid):
        """
        Constructs all the necessary attributes for the transaction object.

        Parameters
        ----------
        sender_hash : bytes
            the  address of a zimcoin user that is willing to send money
        recipient_hash : bytes
            the  address of a zimcoin user to recieve money
        sender_public_key : bytes
            the public key of a zimcoin user that is willing to send money
        amount : int
            the amount of zimcoins to be transfered including fee
        fee : int
            the amount of zimcoins to be paid from the sended as a fee for a transaction
        nonce : int
            the number of the last sender's transaction on the blockchain
        txid : bytes
            the transaction id

        """

        self.sender_hash = sender_hash  
        self.recipient_hash = recipient_hash    
        self.public_key_bytes = sender_public_key
        self.amount = amount 
        self.nonce =  nonce
        self.fee = fee 
        self.signature = sender_signature
        self.txid = txid
        # This defines whether a the transaction is verified
        # and it is used to print the status of the transaction
        self.__verify_tracker = False
    
    def verify(self, sender_balance, sender_previous_nonce):
        """
        Verifies a transaction

        Parameters
        ----------
        sender_balance : int
            the sender's balance
        sender_previous_nonce: int
            the number of sender's previous transaction on the blockchain
            

        Returns
        -------
        txid, signature : dict
            the id and the sender's signature for a verified transaction object
        """
        
        # txid verification
        self.txid_check = update_hash(self.sender_hash, self.recipient_hash,
                                      self.public_key_bytes, self.amount,
                                      self.fee, self.nonce, self.signature)
        if self.txid_check != self.txid:
            raise Exception(f"\n\nVERIFICATION FAILED: Invalid transaction ID\n\n")

        # Signature verification
        try:
            public_key = load_der_public_key(self.public_key_bytes, default_backend())
            (public_key.verify(self.signature, 
                                      b''.join([self.recipient_hash, struct.pack('<Q', self.amount),
                                                struct.pack('<Q', self.fee), 
                                                struct.pack('<Q', self.nonce)]),
                                      ec.ECDSA(hashes.SHA256())))
        except:
            raise Exception("\n\nVERIFICATION FAILED: Invalid signature\n\n")
        

        # Checks for errors in the lenght of receipient's address
        if len(self.recipient_hash) != 20:
            raise Exception("\n\nVERIFICATION FAILED: The receipient's address is not valid\n\n")

        # Checking sender's nonce
        if sender_previous_nonce + 1 != self.nonce:
            raise Exception(f"\n\nVERIFICATION FAILED: Sender's transaction number is not invalid\n\n")
        
        
        # We verify that sender has enough zims (including the fees)
        # to make this transaction
        if sender_balance < int(self.amount):  ####if sender_balance < int(self.amount + self.fee):
            raise Exception(f"\n\nVERIFICATION FAILED: Sender has not enough zimcoins for this transaction\n\n")
        if self.amount not in range(1, sender_balance + 1):
            raise Exception(f"\n\nVERIFICATION FAILED: {self.amount} is not a invalid amount of zimcoins\n\n")
        if self.fee not in range(0, self.amount + 1):
            raise Exception(f"\n\nVERIFICATION FAILED: {self.fee} is not a invalid fee for this transaction\n\n")
        
        # We set the verify_tracker to True so when we print
        # the transaction's instance we get useful information
        # like txid and signature
        self.__verify_tracker = True
        print("SUCCESSFUL VERIFICATION")
        return {"txid": self.txid.hex(),
                "signature": self.signature.hex()}
            
    def __str__(self):
        if self.__verify_tracker:
            return ("\n\n---------VERIFIED TRANSACTION---------\n"+
                    f"Transaction ID: "+
                    f"{self.txid.hex()}\nSender's Signature: "+
                    f"{self.signature.hex()}\n\n".format(self=self)) 
        if not self.__verify_tracker:
            return ("\n\n---------PENDING TRANSACTION (not yet vefified)----------\n"+
                    f"Sender's address: {self.sender_hash.hex()}\nRecipient's address: {self.recipient_hash.hex()}\nAmount to be tranfered: "+
                    f"{self.amount}\nFee to be charged for this transaction: "+
                    f"{self.fee}\n\n**Please note that the sender "+
                    "will be charged with the fee for this transaction**\n\n".format(self=self))  


def create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce):
    """
    Creates a signed transaction object

    Parameters
    ----------
    sender_private_key : Hashlib object
        the senders private key
    recipient_hash : bytes
        the  address of a zimcoin user to recieve money
    amount : int
        the amount of zimcoins to be transfered including fee
    fee : int
        the amount of zimcoins to be paid from the sended as a fee for a transaction
    nonce : int
        the number of the last sender's transaction on the blockchain

        

    Returns
    -------
    tr : transaction object
        a signed transaction object (not yet verified)
    """

    # We generate senders public key in bytes format
    sender_public_key_bytes = public_key_bytes(sender_private_key)
    
    # We are generating sender's signature
    sender_signature = user_signature(sender_private_key, recipient_hash, amount, fee, nonce)
    
    # We generate sender's address
    sender_hash = address(sender_private_key)
    
    # We are generating txid to pass it to the transaction class for verification
    txid = update_hash(sender_hash, recipient_hash,
                       sender_public_key_bytes,amount,
                       fee, nonce, sender_signature)

    # We generate transaction
    tr = Transaction(sender_hash ,recipient_hash,
                 sender_public_key_bytes,
                 amount, fee, nonce, sender_signature, txid)
    
    return tr 

###########################################
##### Code for CW3: Block and Balances ####
###########################################


class UserState:
    """
    A class to keep track of zimcoin users' details on the blockchain.

    ...

    Attributes
    ----------
    balance : int
        the user's balance
    nonce : int
        the number of the user's latest transaction

    Methods
    -------
    None
    """
    def __init__(self, balance, nonce):
        """
        Constructs all the necessary attributes for the UserState object.

        Parameters
        ----------
        balance : int
            the user's balance
        nonce : int
            the number of the user's latest transaction
        """
            
        self.balance = balance
        self.nonce = nonce



class Block:
    """
    A class to represent a block of transactions.

    ...

    Attributes
    ----------
    previous : bytes
        the id of the previous block on the blockchain
    height : int
        The number of the blocks previous integrated on the blockchain.
    miner : bytes
        the address of the miner
    transactions : list
        a list of transactions to be processed by the block
    timestamp : Timestamp object
        the unix time of the generation of the block
    difficulty : int
        the difficulty of the proof of work
    nonce : int
        a value that generates a valid id for a mined block
    block_id : bytes
        a valid id that meets the difficulty criteria for the block


    Methods
    -------
    verify_and_get_changes(previous_user_states, difficulty):
        Verifies transaction.
    """

    def __init__(self, previous, height, miner_hash, transactions,timestamp, difficulty, block_id=None, nonce=None):
        """
        Constructs all the necessary attributes for the block object.

        Parameters
        ----------
        previous : bytes
            the id of the previous block on the blockchain
        height : int
            The number of the blocks previous integrated on the blockchain.
        miner : bytes
            the address of the miner
        transactions : list
            a list of transactions to be processed by the block
        timestamp : Timestamp object
            the unix time of the generation of the block
        difficulty : int
            the difficulty of the proof of work
        nonce : int
            a value that generates a valid id for a mined block
        block_id : bytes
            a valid id that meets the difficulty criteria for the block

        """

        self.previous_block_id = previous #binascii.unhexlify(previous)
        self.height = height
        self.miner = miner_hash
        self.transactions = transactions      
        self.timestamp = timestamp #int(time.time())
        self.difficulty = difficulty
        if self.difficulty not in range(1, 2**128):
            raise Exception("\n\nNot valid difficulty\n\n")
        # nonce and block_id will be populated after mining
        if nonce == None:
            self.nonce = ""
        else:
            self.nonce = nonce
 
        if block_id == None:
            self.block_id = ""
        else:
            self.block_id = block_id
            

        
        
    def verify_and_get_changes(self, difficulty, previous_user_states):
        """
        Verifies a block and returns an updated global record

        Parameters
        ----------
        previous_user_states : dict
            a dictionary that contains all the infromation about the users' status
        difficulty: int
            the expected difficulty of the mined block
            

        Returns
        -------
        global_record : dict
            the updated global record which contains the users' status
        """
        
        # Verifying the type of the global record
        self.global_record = previous_user_states

        # Verifying that the difficulty matches to 
        # the proof of work required to mine the block
        if difficulty != self.difficulty:
            raise Exception("\n\nBLOCK VERIFICATION FAILED: Invalid difficulty\n\n")

        # Verifying that the proof of work criteria are met
        if int(self.block_id, base=16) > 2**256 // difficulty:
            raise Exception("\n\nProof of work criteria not met\n\n")
        
        
        # Verifying the block id provided by the miner
        digest = hashes.Hash(hashes.SHA256())                                        
        digest.update(b''.join([self.previous_block_id, 
                                self.miner, 
                                b''.join([tr.txid for tr in self.transactions]), 
                                self.timestamp.to_bytes(8, byteorder='little'), 
                                self.difficulty.to_bytes(16, byteorder='little'),
                                self.nonce.to_bytes(8, byteorder='little')])) 
        block_id = digest.finalize().hex()
  
        if  block_id != self.block_id:
            raise Exception("\n\nBLOCK VERIFICATION FAILED: Invalid block id\n\n")
            
        
        # Verifying the type and the number of the transactions collection
        if not isinstance(self.transactions, list):
            raise Exception("\n\nTransactions parameter should be a list of transactions\n\n")
        if len(self.transactions) not in range(1, 26):
            raise Exception("\n\nInvalid number of transactions\n\n")
            
        
        # Checks for errors in the lenght of receipient's address
        if len(self.miner) != 20:
            raise Exception("\n\nVERIFICATION FAILED: The receipient's address is not valid\n\n")
        
        # Generating a list to keep track of multiple transaction of users in the same block
        trackMultTrans = []
        
        for tr in self.transactions:
            
            # Keeping track of how many transactions a user have established in the block
            CountTrnsSameUser = trackMultTrans.count(tr.sender_hash)

            if tr.sender_hash in trackMultTrans:
                print (tr)
                # Using the glob_record and to verify transactions from the same sender.
                tr.verify(self.global_record[tr.sender_hash.hex()].balance, self.global_record[tr.sender_hash.hex()].nonce-1-CountTrnsSameUser)
                
                # Updating users' status on global record after verified transactions
                self.global_record[tr.sender_hash.hex()] = UserState(self.global_record[tr.sender_hash.hex()].balance - tr.amount , 
                                                                  self.global_record[tr.sender_hash.hex()].nonce + 1)
                self.global_record[tr.recipient_hash.hex()] = UserState(self.global_record[tr.recipient_hash.hex()].balance + tr.amount - tr.fee, 
                                                                   self.global_record[tr.recipient_hash.hex()].nonce)
                self.global_record[self.miner.hex()] = UserState(self.global_record[self.miner.hex()].balance + tr.fee, 
                                                                  self.global_record[self.miner.hex()].nonce)
                trackMultTrans.append(tr.sender_hash)
                print (tr,2*"\n===========================================================================")
           
            # Verifying unique transactions
            else:
                print (tr)
                if tr.verify(self.global_record[tr.sender_hash.hex()].balance, self.global_record[tr.sender_hash.hex()].nonce-1):
                    
                    # Updating users' status on global record after verified transactions
                    self.global_record[tr.sender_hash.hex()] = UserState(self.global_record[tr.sender_hash.hex()].balance - tr.amount , 
                                                                  tr.nonce+1)
                    self.global_record[tr.recipient_hash.hex()] = UserState(self.global_record[tr.recipient_hash.hex()].balance + tr.amount - tr.fee, 
                                                                      self.global_record[tr.recipient_hash.hex()].nonce)
                    self.global_record[self.miner.hex()] = UserState(self.global_record[self.miner.hex()].balance + tr.fee, 
                                                                      self.global_record[self.miner.hex()].nonce)
                    trackMultTrans.append(tr.sender_hash)
                    print (tr, 2*"\n===========================================================================")
        
        # Update miners record with the reward for mining the block
        self.global_record[self.miner.hex()] = UserState(self.global_record[self.miner.hex()].balance + 10000, 
                                                                      self.global_record[self.miner.hex()].nonce)
        # removing the list not to occupy space in memory
        del trackMultTrans
        return self.global_record


def mining_hash(args, block, targ):
    """
    Mining the block according to the proof of work criteria.
    The parameters into this function are passed via the Block object.

    Parameters
    ----------
    args : itterator
        an iterable passed by multiprocessing to increase hashing speed
    block.previous_block_id : bytes
        the id of the previous block on the blockchain
    block.height : int
        the number of the blocks previous integrated on the blockchain.
    block.miner : bytes
        the address of the miner
    block.transactions : list
        a list of transactions to be processed by the block
    block.timestamp : Timestamp object
        the unix time of the generation of the block
    block.difficulty : int
        the difficulty of the proof of work
    block.nonce : int
        a value that generates a valid id for a mined block
    target : int
        the result of the division of 2^256 by the difficulty
        the block id should be smaller that the target to meet
        the proof of work criteria
        
    Returns
    -------
    c : str
        a hexadecimal representation of a block_id that fulfils the proof of work criteria
    n : 
        a nonce that generates a valid block id
    """
    
    # We select a random nonce within the acceptable range
    n = random.randint(0, 2**64)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b''.join([block.previous_block_id, 
                            block.miner, 
                            b''.join([tr.txid for tr in block.transactions]), 
                            block.timestamp.to_bytes(8, byteorder='little'), 
                            block.difficulty.to_bytes(16, byteorder='little'),
                            n.to_bytes(8, byteorder='little')]))

    c = digest.finalize().hex()
    if int(c , base=16) <= targ:
        return c, n

    
def mine_block(previous, height, miner_hash, transactions,timestamp, difficulty):
    """
    Mining a block with multiprocessing. 
     

    Parameters
    ----------
    previous_block_id : bytes
        the id of the previous block on the blockchain
    height : int
        the number of the blocks previous integrated on the blockchain.
    miner : bytes
        the address of the miner
    transactions : list
        a list of transactions to be processed by the block
    timestamp : Timestamp object
        the unix time of the generation of the block
    difficulty : int
        the difficulty of the proof of work
    
        
    Returns
    -------
    block: Block object
        updates the block's id and nonce and prepares it for verification
    """
    
    block = Block(previous, height, miner_hash, transactions,timestamp, difficulty)
    
    
    
    # Defining the target
    target = 2**256 // block.difficulty
    # Using imap for multiprocessing
    # Each core will run the hashing function 10000 times in each itteration
    # We define a large iterable range(24**24) so to be confident
    # that the passes are sufficient to mine the block
    with multiprocessing.Pool() as p:
        for result in p.imap(partial(mining_hash, block = block, targ = target), 
                             range(24**24), 
                             chunksize=10000): 
            if result:
                #print ("Block_id: ", result[0],"\n\n", "nonce: ", result[1])
                block.block_id = result[0]
                block.nonce = result[1]
                break
                # When the block is mined we terminate the multiprocessing session
                p.terminate()
        return block




