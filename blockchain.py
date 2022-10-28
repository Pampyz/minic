from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
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
            s += bytes(self.script_sig) # Size
        return s

    @staticmethod
    def deserialize(arr):
        prev_hash = arr[0:32]
        prev_index = arr[32:36]
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
            
    def __hash__(self, tx_hash=['SHA256'], skip_scripts=False):
        hash = self.serialize(skip_scripts)
        for h in tx_hash:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(hash)
            hash = digest.finalize()
        return hash

    def serialize(self, skip_scripts=False):
        s = len(self.inputs).to_bytes(4, byteorder='big') # Should actually be VarINT
        for input in self.inputs:
            s += input.serialize(skip_script=skip_scripts)
        
        s += len(self.outputs).to_bytes(4, byteorder='big') # Should actually be VarINT
        for output in self.outputs:
            s += output.serialize()
        
        return s

    @staticmethod
    def deserialize_transactions(arr):
        counter = Counter()

        n_transactions = int.from_bytes(counter.extract(arr, 4), 'big')
        print('Number of transactions in deserialized block: ', n_transactions)

        txs = []
        while n_transactions > 0:
            tx = Transaction()
            n_inputs = int.from_bytes(counter.extract(arr, 4), 'big')
            print('Number of inputs: ', n_inputs)

            inputs = []
            while n_inputs > 0:
                prev_hash = counter.extract(arr, 32)
                prev_index = counter.extract(arr, 4)

                script_length_bytes = counter.extract(arr, 4)
                script_length = int.from_bytes(script_length_bytes, byteorder='big')
                
                script_sig = script_length_bytes + counter.extract(arr, script_length)
                
                inputs.append(Input(prev_hash, prev_index, script_sig))
                n_inputs -= 1

            n_outputs = int.from_bytes(counter.extract(arr, 4), 'big')
            print('Number of outputs: ', n_inputs)

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
        self.version = version # 6 bytes
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

    def __hash__(self):
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
            return txs[0].__hash__()
        else:
            tx1 = txs[0:int(round(len(txs)/2))]
            tx2 = txs[int(round(len(txs)/2)):]
            hash = self.get_merkle_root(tx1) + self.get_merkle_root(tx2)

            sha = hashes.Hash(hashes.SHA256()) ### Might add config functionality here???
            sha.update(hash)
            
            return sha.finalize()

    def mine(self):
        condition = False
        nonce = 1
        while not condition:
            self.header.nonce = nonce
            hash = self.header.__hash__()
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
    def deserialize_header(arr):
        version = str(arr[0:5]) # 5 bytes
        previous_block = arr[5:37] # 32 bytes
        merkle_root = arr[37:69] # 32 bytes
        t = int.from_bytes(arr[69:73], 'big') # 4 bytes
        bits = int.from_bytes(arr[73:105], 'big') # 32 bytes - SHOULD BE 4! Currently difficulty is given in long format.
        nonce = int.from_bytes(arr[105:109], 'big') # 4 bytes

        header = BlockHeader(version = version, previous_block = previous_block, merkle_root=merkle_root, 
                            time = t, bits = bits, nonce = nonce)
        return header

    @staticmethod
    def deserialize(arr):
        block = Block()
        
        block.header = Block.deserialize_header(arr)
        block.txs = Transaction.deserialize_transactions(arr[109:]) 
        return block
        # Validate merkle root, hash < difficulty, validate difficulty with blockstate 

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

class DataContext:

    # To cache: find transaction from a given hash
    # Find all utxo corresponding to an address
    # Find blocks by reference
    
    def __init__(self, config):
        self.data_path = config['data_path']
        self.block_store = os.path.join(self.data_path, 'blocks')

        if not os.path.isdir(self.data_path):
            os.mkdir(self.data_path)
        
        if not os.path.isdir(self.block_store):
            os.mkdir(self.block_store)
        
        #self.block_height

    def store_block(self, block, index):
        # Verify block first
        with open(os.path.join(self.block_store, 'blk-%s' % str(index)), 'wb') as f:
            f.write(block.serialize())

    def load_block(self, index):
        with open(os.path.join(self.block_store, 'blk-%s' % str(index)), 'rb') as f:
            return Block.deserialize(f.read())
        # Also verify the deserialized block

    def index_chain(self):
        pass

# Temporary class for tests. To be removed
class BlockStorage:
    def __init__(self, config):
        self.config = config
        self.hashmap = {}
    
    def store_transaction(self, tx):
        self.hashmap[tx.__hash__(self.config['tx-hash'])] = tx

    def list_transactions(self):
        for k, v in self.hashmap.items():
            print(k, v)
    

class BlockState:
    def __init__(self, pk, config):
        self.config = config

        self.pk = pk
        self.pubkey = self.get_pubkey()
        self.address = self.get_address()

        self.current_block_height = 0
        self.current_reward = 5000000000
        self.fee = 50000000

        self.utxos = []

    # Will be removed and added to DataContext.
    def add_utxo(self, prev_hash, prev_index, value):
        self.utxos.append({'prev_hash': prev_hash, 'prev_index': prev_index, 'value': value})
        return

    def get_pubkey(self):
         # Byte-representation of public key
        pubkey = self.pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pubkey

    def get_address(self):
        # Perform given pub-address-map as given in config (default is SHA3-224(SHA-256))
        address = self.pubkey
        for h in self.config['pub-address-map']:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(address)
            address = digest.finalize()
        return address

    def create_coinbase_output(self):
        script = self.address
        return Output(self.current_reward, script)

    def create_coinbase_input(self):
        dummy_hash = b''
        for h in self.config['pub-address-map']:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(dummy_hash)
            dummy_hash = digest.finalize()

        return Input(dummy_hash, 0, b'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')

    def create_coinbase_transaction(self):
        transaction = Transaction()
        print(len(transaction.inputs), len(transaction.outputs))
        transaction.add_input(self.create_coinbase_input())
        transaction.add_output(self.create_coinbase_output())
        
        print('Coinbase inputs and outputs')
        print(len(transaction.inputs), len(transaction.outputs))
        return transaction

    # Test & debug code
    def create_genesis_header(self, merkle_root):
        genesis_header_reference = hash(b'', ['SHA256', 'SHA256']) 
        target = '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' # 64, original has 8 leading zeroes (self.storage.get_current_target())

        genesis_header = BlockHeader(version = b'0.0.5', previous_block = genesis_header_reference, merkle_root = merkle_root, \
                                    time = int(time.time()), bits = int(target, 16)) 
        return genesis_header

    def create_genesis_block(self):
        # Create initial transaction
        txs = [self.create_coinbase_transaction()]
        genesis_block = Block(txs)

        genesis_header = self.create_genesis_header(genesis_block.get_merkle_root())
        genesis_block.header = genesis_header
        
        nonce = genesis_block.mine()
        genesis_block.header.nonce = nonce

        return genesis_block

    def get_script_sig(self, tx):
        ''' This is a simplified version of the bitcoin scriptsig - called pay-to-pubkey-hash.
            It consists of a signature of the serialized transaction without scriptsigs, concatenated
            with a byte-representation of the public key of the signer. '''

        sig = self.pk.sign(
            tx.__hash__(skip_scripts=True), 
            ec.ECDSA(hashes.SHA256())
        ) # DER-encoding seems to have variable length - see https://stackoverflow.com/questions/17269238/ecdsa-signature-length
        
        sig_length = len(sig).to_bytes(4, byteorder='big')

        pub_key = self.pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Change encoding & format for more crisp transactions
        )

        print('Sig & pubkey lengths: ')
        print(len(sig), len(pub_key))
        return sig_length + sig + pub_key

    ''' Fee is included in value! '''
    def create_transaction(self, value, receiver, mode='fill'):
        tx = Transaction()

        # Start by constructing inputs made from available UTXO
        if mode == 'fill':
            value_ = 0
            sorted_utxos = sorted(self.utxos, key=lambda x: x['value'])
            
            loop_broken = False
            for i in range(0, len(sorted_utxos)):
                utxo = sorted_utxos[i]

                value_ += utxo['value'] 
                tx.add_input(Input(utxo['prev_hash'], utxo['prev_index'], None))

                if value_ > value:
                    loop_broken = True
                    break

            if not loop_broken:
                print('Transaction too big! Insufficient funds.')
                return

        elif mode =='biggest_first':
            pass

        # Create output to receiver address, send change to own address
        tx.add_output(Output(value-self.fee, receiver))
        tx.add_output(Output(value_-value, self.address))
        
        # Finally add signatures to inputs
        script_sig = self.get_script_sig(tx)
        tx.add_script_sigs(script_sig)
        
        return tx

    def validate_value(self, tx, storage):
        total_value = 0
        for x in tx.inputs:
            referred_value = storage.hashmap[x.prev_hash].outputs[x.prev_index].value
            total_value += referred_value

        assert total_value > sum([x.value for x in tx.outputs])    
        fee = total_value - sum([x.value for x in tx.outputs])
        print(fee)
        return

    def validate_inputs(self, tx, storage):
        ''' Validates signatures & addresses '''
        for x in tx.inputs:
            sig_length = int.from_bytes(x.script_sig[0:4], 'big')
            signature = x.script_sig[4:4+sig_length]
            pub_key = x.script_sig[(4 + sig_length) : (4 + sig_length + 174)]

            # Perform given pub-address-map as given in config (default is SHA3-224(SHA-256))
            address = pub_key
            for h in self.config['pub-address-map']:
                digest = eval('hashes.Hash(hashes.%s())' % h)
                digest.update(address)
                address = digest.finalize()
        

            pub_key = serialization.load_pem_public_key(pub_key)
            pub_key.verify(signature, tx.__hash__(skip_scripts=True), ec.ECDSA(hashes.SHA256()))

            address_ = storage.hashmap[x.prev_hash].outputs[x.prev_index].script
            assert address == address_

    def validate_transaction(self, tx, storage):
        # Assert that the tx:s can be found among validated blocks & given values are true
        self.validate_value(tx, storage)

        # Check signatures
        self.validate_inputs(tx, storage)
        return

    def validate_block(self, block, storage):
        pass


    
