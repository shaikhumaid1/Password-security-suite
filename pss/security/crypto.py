import os
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password,salt,time_cost=3,memory_cost=65536,parallelism=2):
    if not password: raise ValueError('Master password cannot be empty.')
    return hash_secret_raw(password.encode(),salt,time_cost,memory_cost,parallelism,32,Type.ID)
def encrypt(key,plaintext,aad=b''):
    nonce=os.urandom(12); return nonce,AESGCM(key).encrypt(nonce,plaintext,aad)
def decrypt(key,nonce,ciphertext,aad=b''):
    return AESGCM(key).decrypt(nonce,ciphertext,aad)
