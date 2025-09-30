import random
import hashlib
import hmac

# Setup Diffie-Hellman parameters (small primes for example only)
p = 467
g = 2

def dh_generate_private_key(p):
    return random.randint(2, p-2)

def dh_generate_public_key(g, priv, p):
    return pow(g, priv, p)

def dh_compute_shared_secret(pub, priv, p):
    return pow(pub, priv, p)

# Alice generates keys
alice_priv = dh_generate_private_key(p)
alice_pub = dh_generate_public_key(g, alice_priv, p)

# Bob generates keys
bob_priv = dh_generate_private_key(p)
bob_pub = dh_generate_public_key(g, bob_priv, p)

# Both compute shared secret
alice_secret = dh_compute_shared_secret(bob_pub, alice_priv, p)
bob_secret = dh_compute_shared_secret(alice_pub, bob_priv, p)

assert alice_secret == bob_secret

shared_key = alice_secret.to_bytes((alice_secret.bit_length() + 7) // 8, 'big')

# Alice "signs" a message by computing HMAC with shared key
message = b"This is Alice's legal document."

alice_hmac = hmac.new(shared_key, message, hashlib.sha256).hexdigest()
print("Alice's HMAC (signature):", alice_hmac)

# Bob receives message and Alice's HMAC, verifies by recomputing HMAC
bob_hmac = hmac.new(shared_key, message, hashlib.sha256).hexdigest()

print("Bob verifies HMAC:", bob_hmac == alice_hmac)
