from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class Input:
    def __init__(self, prev_hash, prev_index, script_sig):
        self.prev_hash = prev_hash
        self.prev_index = prev_index
        self.script_sig = script_sig

    def set_script_sig(self, script_sig):
        self.script_sig = script_sig

    def __serialize__(self):
        s = self.prev_hash
        s += self.prev_index.to_bytes(4, byteorder='big')
        if self.script_sig is not None:
            s += bytes(self.script_sig)
        return s

class Output:
    def __init__(self, value, script):
        self.value = value
        self.script = script

    def __serialize__(self):
        s = self.value.to_bytes(8, byteorder='big')
        s += bytes(self.script)
        return s

class Transaction:
    def __init__(self):
        self.inputs = []
        self.outputs = []

    def add_input(self, input):
        self.inputs.append(input)

    def add_output(self, output):
        self.outputs.append(output)

    def add_script_sigs(self, script_sig):
        for inp in self.inputs:
            inp.set_script_sig(script_sig)
            
    def __hash__(self, tx_hash=['SHA256']):
        hash = self.__serialize__()
        for h in tx_hash:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(hash)
            hash = digest.finalize()
        return hash

    def __serialize__(self):
        s = b''
        
        s += len(self.inputs).to_bytes(4, byteorder='big') # Should actually be VarINT
        for input in self.inputs:
            s += input.__serialize__()
        
        s += len(self.outputs).to_bytes(4, byteorder='big') # Should actually be VarINT
        for output in self.outputs:
            s += output.__serialize__()
        
        return s

class Block:
    def __init__(self):
        self.txs = []

    def __serialize__(self):
        pass

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
        self.address = self.get_address()

        self.current_block_height = 0
        self.current_reward = 5000000000
        self.fee = 50000000

        self.utxos = []

    def add_utxo(self, prev_hash, prev_index, value):
        self.utxos.append({'prev_hash': prev_hash, 'prev_index': prev_index, 'value': value})
        return

    def get_address(self):
        # Byte-representation of public key
        pubkey = self.pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Perform given pub-address-map as given in config (default is SHA3-224(SHA-256))
        address = pubkey
        for h in self.config['pub-address-map']:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(address)
            address = digest.finalize()
        return address

    def create_coinbase_output(self):
        script = self.address
        return Output(self.current_reward, script)

    def create_coinbase_input(self, nonce):
        # Set the nonce to generate unique input transactions for testing purposes
        if nonce is None:
            dummy_hash = b''
        else:
            dummy_hash = nonce

        for h in self.config['pub-address-map']:
            digest = eval('hashes.Hash(hashes.%s())' % h)
            digest.update(dummy_hash)
            dummy_hash = digest.finalize()

        return Input(dummy_hash, 0, b'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')

    def create_coinbase_transaction(self, nonce=None):
        tx = Transaction()
        tx.add_input(self.create_coinbase_input(nonce))
        tx.add_output(self.create_coinbase_output())
        return tx

    def get_script_sig(self, tx):
        return self.pk.sign(
            tx.__hash__(), 
            ec.ECDSA(hashes.SHA256())
        ) + self.address

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

    def verify_transaction(self):
        pass

    ##### Unsure about below stuff. #######
    def mine():
        pass

    
