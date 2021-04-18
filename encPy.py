from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import configparser
import importlib
import argparse
import pickle
import sys

'''
Function sets, retrieves, and parses command line arguments
'''
def get_arguments():
    
    # Initialize Parser
    parser = argparse.ArgumentParser(description="Encrypt a file.")
    
    # Adding commandline arguments
    parser.add_argument('-m', '--mode', help="Encrypt or Decrypt (e or d)")
    parser.add_argument('-f', '--filepath', help="Absolute filepath")
    parser.add_argument('-p', '--password', help="File password")
    parser.add_argument('-o', '--output', help="Decrypted file name")
    
    # Parse and add to object
    args = parser.parse_args()
    
    # If less than two arguments provided
    if len(sys.argv) < 3:
        print('Not all arguments provided.')
        sys.exit
    
    return args

'''
Function reads arguments from config file and passes them as serialized dictionary
'''
def config_handler():
    args = {}
    # Retrieve config information
    config = configparser.ConfigParser()
    config.read('config.cfg')
    hashmode = config['settings']['hashmode']
    crypto_alg = config['settings']['encryptmode']
    file_type = config['settings']['outputfile']
    args["iv_size"] = 8
    key_size = 24
    if 'aes' in crypto_alg.lower():
        crypto_alg = crypto_alg[:3]
        args["iv_size"] = 16
        if '128' in crypto_alg:
            key_size = 16
        else:
            key_size = 32
    else:
        crypto_alg = crypto_alg
    # dynamically import the appropriate libraries
    args["crypto_alg"] = importlib.import_module('Crypto.Cipher.' + crypto_alg)
    args["hashmode"] = importlib.import_module('Crypto.Hash.' + hashmode)
    args["salt"] = get_random_bytes(48)
    args["key_size"] = key_size
    args["count"] = 100000
    args["extension"] = file_type
                 
    return args

'''
Encrypt a file and return bytes to write
'''
def encrypt_file(data, password, args):
    # Generate the master key
    m_key = PBKDF2(password, args["salt"][0:16], args["key_size"], count=args["count"], hmac_hash_module=args["hashmode"])
    # Generate encryption key
    e_key = PBKDF2(m_key, args["salt"][16:32], args["key_size"], count=1, hmac_hash_module=args["hashmode"])
    h_key = PBKDF2(m_key, args["salt"][32:], args["key_size"], count=1, hmac_hash_module=args["hashmode"])
    
    # Generate initialization vector
    initial_v = get_random_bytes(args["iv_size"])
    
    # Create AES cipher object in CBC mode with iv and encryption key
    cipher = args["crypto_alg"].new(e_key, args["crypto_alg"].MODE_CBC, iv=initial_v)
    # Encrypt and create ciphertext - pad data to match block size for CBC
    ciphertext = cipher.encrypt(pad(data, args["crypto_alg"].block_size))
    
    # Create HMAC
    mac = HMAC.new(h_key, digestmod=args["hashmode"])
    # Update the hmac to cover the iv and ciphertext
    mac.update(initial_v + ciphertext)
    args["data"] = mac.digest() + initial_v + ciphertext
    
    # Convert module obj to str for serialization
    args["hashmode"] = args["hashmode"].__name__
    args["crypto_alg"] = args["crypto_alg"].__name__
    
    # serialize dictionary to byte stream
    encrypted_structure = pickle.dumps(args) 
    
    return encrypted_structure

'''
Decrypt File encrypted by this program
'''
def decrypt_file(data, password):    
    args = pickle.loads(data)
    # dynamically load appropriate modules
    args["hashmode"] = importlib.import_module(args["hashmode"])
    args["crypto_alg"] = importlib.import_module(args["crypto_alg"])
    # Get master decrypt key
    md_key = PBKDF2(password, args["salt"][0:16], args["key_size"], count=args["count"], hmac_hash_module=args["hashmode"])
    # Derive encrypt key and hmac key
    de_key = PBKDF2(md_key, args["salt"][16:32], args["key_size"], count=1, hmac_hash_module=args["hashmode"])
    dh_key = PBKDF2(md_key, args["salt"][32:], args["key_size"], count=1, hmac_hash_module=args["hashmode"])

    # Create a decrypt hmac object
    d_mac = HMAC.new(dh_key, digestmod=args["hashmode"])
    d_mac.update(args["data"][d_mac.digest_size:])

    # Retrieve original hmac
    o_mac = args["data"][0:d_mac.digest_size]

    # Compare and authenticate HMAC
    try:
        d_mac.verify(o_mac)
        print("Message is authentic")
    except ValueError:
        print("Message not authenticated")
        sys.exit(1)
    # Retrieve iv
    iv = args["data"][d_mac.digest_size:d_mac.digest_size + args["iv_size"]]
    # Decryption cipher object
    d_cipher = args["crypto_alg"].new(de_key, args["crypto_alg"].MODE_CBC, iv)
    # Decrypted bytes - Remove block size padding
    d_crypt_data = unpad(d_cipher.decrypt(args["data"][d_mac.digest_size + args["iv_size"]:]), args["crypto_alg"].block_size)    
    return d_crypt_data

'''
Handles opening and writing to file and path based on args
'''
def file_handler(options, args):
    # Open file to encrypt in bytes
    file = open(options.filepath, "rb")
    data = file.read()
    file.close()
    
    # Decide to encrypt or decrypt
    if options.mode == 'e':
        # Encrypt the file
        ecn_file = encrypt_file(data, options.password, args)
        # Write and save encrypted data bytes as file
        file = open(options.filepath + args["extension"], "wb")
        file.write(ecn_file)
        file.close()
    else:
        dec_file = decrypt_file(data, options.password)
        file = open(options.output, "wb")
        file.write(dec_file)
        file.close()
        
options = get_arguments()
args = config_handler()
file_handler(options, args)
        
        
    
       
    
    