from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from blockchain import BlockState, DataContext, Block, BlockHeader, Transaction, Input, Output
from tests import test_coinbase_transactions, test_load_and_store
import argparse
import yaml
import os
import time

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

# Main entry point
def main():

    print('-------------------------------------------------------------------- \n'+
            'Welcome to MINIC - a minimal bitcoin-like cryptocurrency application\n' + 
        '--------------------------------------------------------------------\n'
    )
    
    args = parse_args()
    config = parse_config(args.config_path)
    pk = check_key(config)
    
    node = BlockState(pk, config) # Alternatively: node = BlockState(config), node.check_key()
    storage = DataContext(config)

    # test_coinbase_transactions(config, node)
    # test_load_and_store(config, node, storage)

    


if __name__=='__main__':
    main()