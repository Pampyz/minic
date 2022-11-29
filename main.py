from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from blockchain import Block, BlockHeader, Transaction, Input, Output
from contexts import BlockState, DataContext
from tests import test_coinbase_transactions, test_load_and_store
import argparse
import yaml
import os

# Arguments & configs
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", help='Print the status of the application')
    parser.add_argument("--config_path", help='Path to config file', default='./config.yml')
    args = parser.parse_args()
    return args

def parse_config(config_path):
    with open(config_path, 'r') as conf:
        try:
            return yaml.safe_load(conf)
        except yaml.YAMLError as exc:
            print('Error reading config file! YAML-error: ', exc)
            quit()

# Key generation & handling
def generate_key(config):
    pk = ec.generate_private_key(
        eval('ec.%s()' % config['elliptic_curve'])
    )
    return pk

def save_key(pk, p, key_path):
    serialized_private = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(p, 'utf-8'))
    )
    with open(key_path, 'wb') as bfile:
        bfile.write(serialized_private)
    return
    
def load_key(key_path, p):
    with open(key_path, 'rb') as bfile:
        try:
            pk = serialization.load_pem_private_key(bfile.read(), bytes(p, 'utf-8'))
        except:
            print('Error decoding private key! Try another password.')
            quit()
    return pk

            
def check_key(config):
    key_path = config['key_path']
    if os.path.exists(key_path):
        p = input('Please enter your password!: \n')
        return load_key(key_path, p)
    else:
        p1 = input('You currently lack a wallet - you need to generate one! Please enter a password for your wallet (and make sure to remember it)!: \n')
        p2 = input('Please enter the password again!: \n')
        if p1==p2:
            pk = generate_key(config)
            save_key(pk, p1, key_path)
            return pk
        else:
            print('Password mismatch! Please try again!')
            quit()


def test_genesis_block(node):
    ''' put somewhere else later on'''
    genesis_block = node.create_genesis_block()
    genesis_block.cleartext_dump()
    
    node.data_context.store_block(genesis_block, 1)

    genesis_block_ = node.data_context.load_block(1)
    genesis_block_.cleartext_dump()


    print(genesis_block.txs[0].cleartext_dump(), genesis_block_.txs[0].cleartext_dump())
    
    assert genesis_block.header.serialize() == genesis_block_.header.serialize()

    s1 = genesis_block.serialize()
    s2 = genesis_block_.serialize()
    assert s1==s2

# Main entry point
def main():

    print('-------------------------------------------------------------------- \n'+
            'Welcome to MINIC - a minimal bitcoin-like cryptocurrency application\n' + 
        '--------------------------------------------------------------------\n'
    )
    
    args = parse_args()
    config = parse_config(args.config_path)
    pk = check_key(config) # Alternatively: node = BlockState(config), node.check_key()
    
    node = BlockState(pk, config) 
    
    node.data_context.index_chain()
    txs = node.data_context.get_utxos(node.address)
    print('UTXO:s from adress: ', node.address)
    print(txs)

    tx = node.create_transaction(5000000, 50000, node.address)
    print(tx.inputs, tx.outputs)


if __name__=='__main__':
    main()