from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import leveldb
import os
import time

def hash(x, mode=None):
    if mode is None:
        sha = hashes.Hash(hashes.SHA256())
        sha.update(x)
        x = sha.finalize()
    else:
        for z in mode:
            sha = eval('hashes.Hash(hashes.%s())' % z)
            sha.update(x)
            x = sha.finalize()
    return x


class Input:
    def __init__(self, prev_hash, prev_index, script_sig):
        self.prev_hash = prev_hash
        self.prev_index = prev_index
        self.script_sig = script_sig

    def set_script_sig(self, script_sig):
        self.script_sig = script_sig

    def serialize(self, skip_script=False):
        s = self.prev_hash
        s += self.prev_index.to_bytes(4, byteorder='big')
        if not skip_script:
            s_ = bytes(self.script_sig)
            s += len(s_).to_bytes(4, byteorder='big')  # Size of scriptsig
            s += s_
        return s

    @staticmethod
    def deserialize(arr):
        prev_hash = arr[0:32]
        prev_index = int.from_bytes(arr[32:36], 'big')
        script_sig = arr[36::]
        return Input(prev_hash, prev_index, script_sig)


class Output:
    def __init__(self, value, script):
        self.value = value
        self.script = script

    def set_script(self, script):
        self.script = script

    def serialize(self):
        s = self.value.to_bytes(8, byteorder='big')
        s += bytes(self.script) # Size
        return s

    @staticmethod
    def deserialize(arr):
        value = arr[0:8]
        script = arr[8:]
        return Output(value, script)

class Transaction:
    def __init__(self):
        self.inputs = []
        self.outputs = []

    def add_input(self, i):
        self.inputs.append(i)

    def add_output(self, o):
        self.outputs.append(o)

    def add_script_sigs(self, script_sig):
        for input in self.inputs:
            input.set_script_sig(script_sig)
            
    def hash(self, tx_hash=['SHA256'], skip_scripts=False):
        hash = self.serialize(skip_scripts)
        for h in tx_hash:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(hash)
            hash = digest.finalize()
        return hash

    def cleartext_dump(self):
        print('------ Summarizing transaction ------')
        print('Number of inputs: ', len(self.inputs))
        print('Number of outputs: ', len(self.outputs))
        print('Input hashes, indices and scriptsigs: ', [(i.prev_hash, i.prev_index, i.script_sig)for i in self.inputs])
        print('Output values and addresses: ', [(o.value, o.script) for o in self.outputs])

    def serialize(self, skip_scripts=False):
        s = len(self.inputs).to_bytes(4, byteorder='big') # Should actually be VarINT
        for input in self.inputs:
            s += input.serialize(skip_script=skip_scripts)
        
        s += len(self.outputs).to_bytes(4, byteorder='big') # Should actually be VarINT
        for output in self.outputs:
            s += output.serialize()
        
        return s

    @staticmethod
    def deserialize(arr):
        counter = Counter()

        n_transactions = int.from_bytes(counter.extract(arr, 4), 'big')
        print('Deserializing block! Number of transactions in deserialized block: ', n_transactions)

        txs = []
        while n_transactions > 0:
            tx = Transaction()
            n_inputs = int.from_bytes(counter.extract(arr, 4), 'big')
            print('Number of inputs: ', n_inputs)

            inputs = []
            while n_inputs > 0:
                prev_hash = counter.extract(arr, 28)
                prev_index = counter.extract(arr, 4)
                prev_index = int.from_bytes(prev_index, byteorder='big')

                script_length_bytes = counter.extract(arr, 4)
                script_length = int.from_bytes(script_length_bytes, byteorder='big')

                print('Length of script: ', script_length)
                
                script_sig = counter.extract(arr, script_length)
                
                inputs.append(Input(prev_hash, prev_index, script_sig))
                n_inputs -= 1

            n_outputs = int.from_bytes(counter.extract(arr, 4), 'big')
            print('Number of outputs: ', n_outputs)

            outputs = []
            while n_outputs > 0:
                value = int.from_bytes(counter.extract(arr, 8), byteorder='big')
                script = counter.extract(arr, 28)
                outputs.append(Output(value, script))
                n_outputs -= 1

            n_transactions -= 1

            tx.inputs = inputs
            tx.outputs = outputs
            txs.append(tx)
        return txs

class BlockHeader:
    def __init__(self, version, previous_block, merkle_root, time, bits, nonce=None):
        self.version = version # 5 bytes
        self.previous_block = previous_block # Hash
        self.merkle_root = merkle_root # Hash
        self.time = time # 4 bytes / 32 bytes depends on implementation
        self.bits = bits # 4 bytes

        if nonce is None: # 4 bytes
            self.nonce = 0 
        else:
            self.nonce = nonce

    def serialize(self):
        t = self.time.to_bytes(4, byteorder='big')
        bits = self.bits.to_bytes(32, byteorder='big')
        nonce = self.nonce.to_bytes(4, byteorder='big')

        return self.version + self.previous_block + self.merkle_root + t + bits + nonce

    @staticmethod
    def deserialize(arr):
        version = arr[0:5] # 5 bytes
        previous_block = arr[5:37] # 32 bytes
        merkle_root = arr[37:69] # 32 bytes
        t = int.from_bytes(arr[69:73], 'big') # 4 bytes
        bits = int.from_bytes(arr[73:105], 'big') # 32 bytes - SHOULD BE 4! Currently difficulty is given in long format.
        nonce = int.from_bytes(arr[105:109], 'big') # 4 bytes

        header = BlockHeader(version = version, previous_block = previous_block, merkle_root=merkle_root, 
                            time = t, bits = bits, nonce = nonce)
        return header

    def hash(self):
        hash = self.serialize()
        for i in range(0, 2):
            sha = hashes.Hash(hashes.SHA256())
            sha.update(hash)
            hash = sha.finalize()    
        return hash


class Block:
    def __init__(self, txs = []):
        self.header = []
        self.txs = txs

    def add_transaction(self, tx):
        self.txs.append(tx)

    def get_merkle_root(self, txs=None):
        if txs is None:
            txs = self.txs

        if len(txs) == 1:
            return txs[0].hash()
        else:
            tx1 = txs[0:int(round(len(txs)/2))]
            tx2 = txs[int(round(len(txs)/2)):]
            h = self.get_merkle_root(tx1) + self.get_merkle_root(tx2)

            sha = hashes.Hash(hashes.SHA256()) ### Might add config functionality here???
            sha.update(h)
            
            return sha.finalize()

    def mine(self):
        condition = False
        nonce = 1
        while not condition:
            self.header.nonce = nonce
            hash = self.header.hash()
            hash = int.from_bytes(hash, 'big')

            if hash < self.header.bits:
                condition = True
            else:
                nonce += 1
        return nonce

    def cleartext_dump(self):
        ''' Prints a cleartext summary of the block and its contents. '''
        print('------- Summarizing block -------')
        print('Number of transactions: ', len(self.txs))
        print('Time of block publication: ', time.asctime(time.localtime(self.header.time)))
        print('Previous block reference: ', self.header.previous_block)
        print('Merkle root: ', self.header.merkle_root)
        print('Difficulty: ', self.header.bits)
        print('Nonce: ', self.header.nonce)

    def hash(self):
        hash = self.serialize()
        for i in range(0, 2):
            sha = hashes.Hash(hashes.SHA256())
            sha.update(hash)
            hash = sha.finalize()    
        return hash

    def serialize(self):
        ser = self.header.serialize()
        ser += len(self.txs).to_bytes(4, byteorder='big')
        for x in self.txs:
            ser += x.serialize()
        return ser

    @staticmethod
    def deserialize(arr):
        block = Block()
        
        block.header = BlockHeader.deserialize(arr)
        block.txs = Transaction.deserialize(arr[109:])
        
        return block

class Counter():
    def __init__(self, start=0, end=0):
        self.start = start
        self.end = end

    def increment(self, offset):
        self.start = self.end
        self.end += offset

    def extract(self, arr, offset):
        self.increment(offset)
        return arr[self.start:self.end]