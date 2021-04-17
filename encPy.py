from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import configparser
import importlib
import argparse
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
    parser.add_argument('-o', '--output', help="Output filename")
    
    # Parse and add to object
    args = parser.parse_args()
    
    # If less than two arguments provided, 
    if len(sys.argv) < 3:
        print('Not all arguments provided.')
        sys.exit
    
    return args

'''
Function reads arguments from config file and passes them on as array
'''
def read_config():
    args = []
    # Retrieve config information
    config = configparser.ConfigParser()
    config.read('config.cfg')
    hashmode = config['settings']['hashmode']
    crypto_alg = config['settings']['encryptmode']
    args.append(importlib.import_module('Crypto.Hash.' + hashmode))
    args.append(importlib.import_module('Crypto.Cipher.' + crypto_alg))
    return args

'''
Encrypt a file and return bytes to write
'''
def encrypt_file(data, password, args):
    # Generate the needed salt bytes
    salt = get_random_bytes(48)
    # Generate the master key
    m_key = PBKDF2(password, salt[0:16], count=1000000, hmac_hash_module=args[0])
    # Generate encryption key
    e_key = PBKDF2(m_key, salt[16:32], count=1, hmac_hash_module=args[0])
    h_key = PBKDF2(m_key, salt[32:], count=1, hmac_hash_module=args[0])

    # Create HMAC
    mac = HMAC.new(h_key, digestmod=args[0])
    
    # Generate initialization vector
    initial_v = get_random_bytes(16)
    
    # Create AES cipher object in CBC mode with iv and encryption key
    cipher = args[1].new(e_key, args[1].MODE_CBC, iv=initial_v)
    # Encrypt and create ciphertext - pad data to match block size for CBC
    ciphertext = cipher.encrypt(pad(data, args[1].block_size))
    
    # Update the hmac
    mac.update(salt + initial_v + ciphertext)
    
    return mac.digest() + salt + initial_v + ciphertext

'''
Decrypt File encrypted by this program
'''
def decrypt_file(data, password, args):    
    # Retrieve needed salt
    d_salt = data[64:112]
    # Get master decrypt key
    md_key = PBKDF2(password, d_salt[0:16], count=1000000, hmac_hash_module=args[0])
    # Derive encrypt key and hmac key
    de_key = PBKDF2(md_key, d_salt[16:32], count=1, hmac_hash_module=args[0])
    dh_key = PBKDF2(md_key, d_salt[32:], count=1, hmac_hash_module=args[0])
    # Create a decrypt hmac object
    d_mac = HMAC.new(dh_key, digestmod=args[0])
    d_mac.update(data[64:])
    # Retrieve original hmac
    o_mac = data[0:64]
    # Compare and authenticate HMAC
    try:
        d_mac.verify(o_mac)
        print("Message is authentic")
    except ValueError:
        print("Message not authenticated")
        sys.exit(1)
    # Retrieve iv
    iv = data[112:128]
    # Decryption cipher object
    d_cipher = args[1].new(de_key, args[1].MODE_CBC, iv)
    # Decrypted bytes - Remove block size padding
    d_crypt_data = unpad(d_cipher.decrypt(data[128:]), args[1].block_size)    
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
        file = open(options.output, "wb")
        file.write(ecn_file)
        file.close()
    else:
        dec_file = decrypt_file(data, options.password, args)
        file = open(options.output, "wb")
        file.write(dec_file)
        file.close()
        
options = get_arguments()
args = read_config()
file_handler(options, args)
        
        
    
       
    
    