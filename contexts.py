from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blockchain import Block, BlockHeader, Transaction, Input, Output

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

class DataContext:
    def __init__(self, config, address):
        self.data_path = config['data_path']
        self.block_store = os.path.join(self.data_path, 'blocks')
        
        if not os.path.isdir(self.data_path):
            os.mkdir(self.data_path)
        
        if not os.path.isdir(self.block_store):
            os.mkdir(self.block_store)
        
        self.index_db = leveldb.LevelDB(os.path.join(self.data_path, 'index')) # Hash of block -> index of block on file
        self.chainstate_db = leveldb.LevelDB(os.path.join(self.data_path, 'chainstate')) # (Address -> utxos) && utxo -> blockheader hash & offset 

        self.address = address

        self.current_block_height = 0
        self.current_reward = 5000000000
        self.fee = 50000000


    def new_block(self, block):
        pass

    def store_block(self, block, index):
        with open(os.path.join(self.block_store, 'blk-%s' % str(index)), 'wb') as f:
            f.write(block.serialize())

    def load_block(self, index):
        with open(os.path.join(self.block_store, 'blk-%s' % str(index)), 'rb') as f:
            return Block.deserialize(f.read())

    def index_chain(self):
        n_blocks = len(os.listdir(self.block_store))
        self.current_block_height = n_blocks

        for i in range(n_blocks):
            block = self.load_block(i+1)
            
            block.cleartext_dump()
            block.txs[0].cleartext_dump()

            self.process_block(block, i+1)

        # verification?
        # self.current_fee...
        # self.current_reward...
        # self.current_difficulty...

    def get_utxos(self, address):
        serialized_utxos = self.chainstate_db.Get(address) # Serialized representation of all UTXO:s for each address
        nbr_of_utxos = len(serialized_utxos)//36 # Length of each UTXO representation: 36 bytes
        
        utxos = []
        for i in range(nbr_of_utxos):
            utxo = serialized_utxos[(36*i):(36*(i+1))] # Extract serialized representation of one utxo
            
            tx_hash = utxo[0:32]
            output_index = int.from_bytes(utxo[32:26],'big')
            print('Reference: ', [tx_hash, output_index])

            tx = self.get_transaction_from_utxo(utxo)
        
            utxos.append({'hash': tx_hash, 
                            'index': output_index, 
                                'value': tx.outputs[output_index].value})

        return utxos

    def get_transaction_from_utxo(self, utxo):
        block_identifier = self.chainstate_db.Get(utxo) # In what block is the utxo? Block_identifier - hash + index of transaction
        block_hash = block_identifier[0:32]
        transaction_index = int.from_bytes(block_identifier[32:36], 'big')

        local_block_index = int.from_bytes(self.index_db.Get(block_hash), 'big')
        block = self.load_block(local_block_index)

        tx = block.txs[transaction_index]
        return tx


    def process_block(self, block, index):
        self.index_db.Put(block.header.hash(), index.to_bytes(4, byteorder='big'))
    
        for i, tx in enumerate(block.txs):
            for j, oput in enumerate(tx.outputs):
                # For every output - add UTXO to map: address -> utxo (tx-hash + offset) 
                utxo = tx.hash() + j.to_bytes(4, byteorder='big')
                address = oput.script

                try:
                    utxos = self.chainstate_db.Get(address)
                    utxos += utxo
                
                except KeyError as e:
                    utxos = utxo

                print('UTXOs corresponding to address: ', utxos)
                self.chainstate_db.Put(address, utxos)

                # For every utxo - add Block to map: utxo -> block (blockheader-hash + offset)
                self.chainstate_db.Put(utxo, block.header.hash() + i.to_bytes(4, byteorder='big'))
                

            for iput in tx.inputs:
                pub_key = iput.script_sig[-154:]
                print('This is the pub key (coinbase): ', pub_key)
                prev_hash = iput.prev_hash
                prev_index = iput.prev_index
                print(pub_key, prev_hash, prev_index)

        return 
        

class BlockState:
    def __init__(self, pk, config):
        self.config = config

        self.pk = pk
        self.pubkey = self.get_pubkey()
        self.address = self.get_address()

        self.data_context = DataContext(config, self.address)

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
        return Output(self.data_context.current_reward, script)

    def create_coinbase_input(self):
        dummy_hash = b''
        for h in self.config['pub-address-map']:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(dummy_hash)
            dummy_hash = digest.finalize()

        return Input(dummy_hash, 0, b'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')

    def create_coinbase_transaction(self):
        transaction = Transaction()

        transaction.add_input(self.create_coinbase_input())
        transaction.add_output(self.create_coinbase_output())
        
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
            tx.hash(skip_scripts=True), 
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

    def build_transaction_smallest_first(self, value, tx):
        value_ = 0

        utxos = self.data_context.get_utxos(self.address)
        sorted_utxos = sorted(utxos, key=lambda x: x['value'])

        loop_broken = False
        for i in range(0, len(sorted_utxos)):
            utxo = sorted_utxos[i]

            value_ += utxo['value'] 
            tx.add_input(Input(utxo['hash'], utxo['index'], None))

            if value_ > value:
                loop_broken = True
                break

        if not loop_broken:
            print('Transaction too big! Insufficient funds.')
            return None

        return tx, value_

    ''' Fee is included in value! '''
    def create_transaction(self, value, fee, receiver, mode='smallest_first'):
        tx = Transaction()

        # Start by constructing inputs made from available UTXO
        if mode == 'smallest_first':
            tx, value_ = self.build_transaction_smallest_first(value+fee, tx)

        # Create output to receiver address, send change to own address

        tx.add_output(Output(value, receiver)) # Send value to receiver
        tx.add_output(Output(value_-(value + fee), self.address)) # Send change back to us (sum of inputs minus sent & fee)
        
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