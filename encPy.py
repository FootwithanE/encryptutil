#!/usr/bin/env python3
"""
@author: Stephen Foote

April 22, 2021

This python file can be used in conjunction with the associated configuration
file to encrypt and decrypt files using an end-user provided password.

This program supports AES128, AES256, and Triple DES (3DES) along with HMAC-HASH
SHA256 or SHA512.

100000  iterations = .07 seconds
1000000 iterations = .71 seconds
1250000 iterations = .91 seconds
"""

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import configparser
import importlib
import argparse
import pickle
import time
import sys

def get_arguments():
    """
    This function is used to collect the end-user provided, commandline
    arguments. Information regarding the required commandline arguments
    can also be accessed through the -h or --help commands.
    
    :return: namespace object with provided arguments
    """    
    # Initialize Parser object
    parser = argparse.ArgumentParser(description="Encrypt a file.")
    
    # Adding commandline arguments
    parser.add_argument('-m', '--mode', help="Encrypt or Decrypt (e or d)")
    parser.add_argument('-f', '--filepath', help="Absolute filepath / filename")
    parser.add_argument('-p', '--password', help="File password")
    parser.add_argument('-o', '--output', help="Decrypted filename")
    
    # Parse commandline and add to options object
    args = parser.parse_args()
    
    # If less than three arguments provided
    if len(sys.argv) < 3:
        print('Not all arguments provided.')
        sys.exit
    
    return args

def config_handler():
    '''
    Function reads arguments provided in the configuration file and builds
    a header with information needed to complete encryption and decryption.
    
    :return: dictionary with required header information
    '''
    # Retrieve config file information
    config = configparser.ConfigParser()
    config.read('enc_config.cfg')
    
    hashmode = config['settings']['hashmode']
    crypto_alg = config['settings']['encryptmode']
    file_type = config['settings']['outputfile']
    iterations = int(config['settings']['iterations'])
    kdf_type = config['settings']['kdftype']
    iv_size = 8
    key_size = 24
    
    # Make changes to IV and Key sized based on algorithm selected
    if 'aes' in crypto_alg.lower():
        crypto_alg = crypto_alg[:3]
        iv_size = 16
        if '128' in crypto_alg:
            key_size = 16
        else:
            key_size = 32
    else:
        crypto_alg = crypto_alg
    
    # Build header with algorithm information
    header = {}
    header["iv_size"] = iv_size
    header["salt"] = get_random_bytes(48)
    header["count"] = iterations
    header["extension"] = file_type    
    header["key_size"] = key_size
    header["kdf_type"] = kdf_type
    
    # dynamically import the appropriate libraries
    header["crypto_alg"] = importlib.import_module('Crypto.Cipher.' + crypto_alg)
    header["hashmode"] = importlib.import_module('Crypto.Hash.' + hashmode)
                 
    return header

def encrypt_file(data, password, header):
    '''
    Encrypts a file and return bytes to write to new file. Header dictionary is built out with
    remaining necessary information and encrypted data is added to the dictionary. The dictionary is
    then serialized in order to write to a file.
    
    :param data: the file data (in bytes) to be encrypted
    :param password: the end-user defined password used to derive the master key
    :param header: a dictionary containing the required information for encryption
    :return: a serialized dictionary containing encrypted data and required decryption information
    '''
    # Generate the master key and two derived keys for encryption and hmac
    start = time.time()
    master_key = PBKDF2(password, header["salt"][0:16], header["key_size"], count=header["count"], hmac_hash_module=header["hashmode"])
    end = time.time()
    print(end - start)
    encrypt_key = PBKDF2(master_key, header["salt"][16:32], header["key_size"], count=1, hmac_hash_module=header["hashmode"])
    mac_key = PBKDF2(master_key, header["salt"][32:], header["key_size"], count=1, hmac_hash_module=header["hashmode"])
    
    # Generate initialization vector
    initial_v = get_random_bytes(header["iv_size"])
    # Create cipher object in CBC mode with specified iv and derived encryption key
    cipher = header["crypto_alg"].new(encrypt_key, header["crypto_alg"].MODE_CBC, iv=initial_v)
    # Encrypt and create ciphertext
    # Pad data to match block size for encryption mode
    ciphertext = cipher.encrypt(pad(data, header["crypto_alg"].block_size))
    
    # Create HMAC object
    mac = HMAC.new(mac_key, digestmod=header["hashmode"])
    # Update the hmac to cover the iv and ciphertext
    mac.update(initial_v + ciphertext)
    header["data"] = mac.digest() + initial_v + ciphertext
    
    # Convert module obj to str for serialization
    header["hashmode"] = header["hashmode"].__name__
    header["crypto_alg"] = header["crypto_alg"].__name__
    
    # Serialize dictionary to byte stream for file writing
    encrypted_structure = pickle.dumps(header) 
    
    return encrypted_structure

def decrypt_file(data, password):
    '''
    Decrypt a file that was encrypted by this same program. The output will be written back to a file
    named by that specified in the end-user provided commandline arguments.
    
    :param data: the encrypted file data (in bytes) to be decrypted
    :param password: the end-user defined password used to derive the master key
    :return: decrypted file data in it's original form
    '''
    # De-serialize the file into a dictionary object    
    header = pickle.loads(data)
    # dynamically load appropriate encryption and hashing modules
    header["hashmode"] = importlib.import_module(header["hashmode"])
    header["crypto_alg"] = importlib.import_module(header["crypto_alg"])
    # Derive the master key
    master_key = PBKDF2(password, header["salt"][0:16], header["key_size"], count=header["count"], hmac_hash_module=header["hashmode"])
    # Derive encrypt key and hmac key
    encrypt_key = PBKDF2(master_key, header["salt"][16:32], header["key_size"], count=1, hmac_hash_module=header["hashmode"])
    mac_key = PBKDF2(master_key, header["salt"][32:], header["key_size"], count=1, hmac_hash_module=header["hashmode"])

    # Create a decrypt hmac object
    mac = HMAC.new(mac_key, digestmod=header["hashmode"])
    mac.update(header["data"][mac.digest_size:])

    # Retrieve the original hmac
    o_mac = header["data"][0:mac.digest_size]

    # Compare and authenticate HMAC
    try:
        mac.verify(o_mac)
        print("Message is authentic")
    except ValueError:
        print("Message not authenticated")
        sys.exit(1)
        
    # Retrieve the iv - separating it from the encrypted data
    iv = header["data"][mac.digest_size:mac.digest_size + header["iv_size"]]
    # Create a cipher object for decryption
    d_cipher = header["crypto_alg"].new(encrypt_key, header["crypto_alg"].MODE_CBC, iv)
    # Decrypt the data and remove block size padding
    d_crypt_data = unpad(d_cipher.decrypt(header["data"][mac.digest_size + header["iv_size"]:]), header["crypto_alg"].block_size)
        
    return d_crypt_data

def file_handler(args, header):
    '''
    Handles opening files, directing the data to the appropriate encryption or decryption functions.
    This function also handles writing the returned data (encrypted or decrypted) to a file.
    
    :param args: namespace object created from the commandline arguments
    :param header: dictionary object containing encryption specifications
    '''
    # Open file to encrypt or decrypt, in bytes
    try:
        with open(args.filepath, "rb") as file:
            data = file.read()
            file.close()
    except IOError:
        print("File could not be located.")
        sys.exit(1)
    
    # Decide to encrypt or decrypt
    if args.mode == 'e':
        # Encrypt the file
        ecn_file = encrypt_file(data, args.password, header)
        # Write and save encrypted data bytes as file
        file = open(args.filepath + header["extension"], "wb")
        file.write(ecn_file)
        file.close()
    else:
        dec_file = decrypt_file(data, args.password)
        file = open(args.output, "wb")
        file.write(dec_file)
        file.close()
        
if __name__ == '__main__':
    # Retrieve commandline arguments
    args = get_arguments()
    # Retrieve configuration arguments and build header
    header = config_handler()
    # Handle file and encryption or decryption
    file_handler(args, header)
