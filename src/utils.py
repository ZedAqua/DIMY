import os
import random
import hashlib
from secretsharing import SecretSharer


UDP_PORT = 10000

def generate_ephid():
    """Generate a 32-byte ephemeral ID (EphID)"""
    return os.urandom(32)

# Shamir's Secret Sharing
def generate_shares(n, m, ephid):
    ephid_int = int.from_bytes(ephid, 'big')
    ephid_hex = ephid_int.to_bytes(32, 'big').hex()
    shares = SecretSharer.split_secret(ephid_hex, m, n)
    return [(i+1, share.split('-')[1]) for i, share in enumerate(shares)]

def reconstruct_secret(shares):
    formatted_shares = [f"{share[0]}-{share[1]}" for share in shares]
    hex_secret = SecretSharer.recover_secret(formatted_shares)
    # Ensure the length of hex_secret is even
    if len(hex_secret) % 2 != 0:
        hex_secret = '0' + hex_secret
    return bytes.fromhex(hex_secret)

# Hash function
def hash_ephid(ephid):
    """Generate SHA-256 hash of EphID"""
    return hashlib.sha256(ephid).hexdigest()

# Diffie-Hellman (DH) key exchange
def generate_dh_keypair(p, g):
    """Generate DH key pair"""
    private_key = random.randint(1, p-1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_secret(private_key, other_public_key, p):
    """Compute shared secret"""
    shared_secret = pow(other_public_key, private_key, p)
    return shared_secret
