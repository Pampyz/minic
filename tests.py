class BlockStorage:
    def __init__(self, config):
        self.config = config
        self.hashmap = {}
    
    def store_transaction(self, tx):
        self.hashmap[tx.__hash__(self.config['tx-hash'])] = tx

    def list_transactions(self):
        for k, v in self.hashmap.items():
            print(k, v)

def test_load_and_store(config, node, storage):
    print(node.create_coinbase_transaction().inputs)
    # Routines for Genesis block
    genesis_block = node.create_genesis_block()
    genesis_block.cleartext_dump()
    
    storage.store_block(genesis_block, index=1)
    block = storage.load_block(1)

    block.cleartext_dump()

    print(len(genesis_block.txs[0].inputs))
    print(genesis_block.txs[0].inputs[0].serialize())
    print(len(block.txs))
    #print(genesis_block.txs[0].serialize())
    #print(block.txs[0].serialize())

def test_coinbase_transactions(config, node):
    storage = BlockStorage(config)
    for i in range(1, 50):
        mining_tx = node.create_coinbase_transaction()
        print(len(mining_tx.inputs))
        storage.store_transaction(mining_tx)
        node.add_utxo(mining_tx.__hash__(), 0, mining_tx.outputs[0].value) # Indexer should fix this

    print('Stored transactions & UTXOS: ')
    storage.list_transactions()
    for x in node.utxos:
        print(x)

    tx = node.create_transaction(25000000000, node.address)
    print([x for x in tx.inputs])
    print([x for x in tx.outputs])
    print(tx.__hash__())
    node.validate_transaction(tx, storage)